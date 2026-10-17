//! Independently checks the metadata of an actual source-issued partial report.
//!
//! These inspections cover report identity and class separation only. They do
//! not authorize the remaining behavioral population or an ordinary provider.
//! The inspected original report is retained as an immutable predecessor; a
//! later report must never substitute its own identity into this evidence.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{
    Bytes, CaptureScope, ContentRef, Continuation, GuaranteeProfile, NodeDescriptor,
    OperatingContract, OperatingMode, Repeatability, canonical,
};
use serde::Serialize;

use super::harness::CandidateHarnessResult;
use crate::node_qualification::{
    CaseKind, CaseVerdict, IssuedQualification, QualificationClaim, QualificationClass,
    QualificationError, RequirementDisposition, WitnessCriterion,
};

/// Retains complete original inputs to these narrowly scoped source inspections.
#[derive(Serialize)]
pub(super) struct OriginalMetadataInspection {
    schema: &'static str,
    original_report: ContentRef,
    original_report_bytes: Bytes,
    original_native: ContentRef,
    original_retirement: ContentRef,
    exact_unit_objects: Vec<MetadataObject>,
    reviews: Vec<MetadataReview>,
    counterfactuals: Vec<MetadataCounterfactual>,
}

#[derive(Serialize)]
struct MetadataObject {
    reference: ContentRef,
    bytes: Bytes,
}

#[derive(Serialize)]
struct MetadataReview {
    requirement: &'static str,
    property: &'static str,
    case_kind: CaseKind,
    limitations: &'static str,
}

#[derive(Serialize)]
struct MetadataCounterfactual {
    case: String,
    observation_kind: &'static str,
    changed_report: ContentRef,
    changed_report_bytes: Bytes,
    original_refusal: &'static str,
}

/// Declares the inspected branches before creating the original native peers.
pub(super) fn fixture() -> serde_json::Value {
    serde_json::json!({
        "schema":"crucible.reference.report-metadata-inspection-fixture.v1",
        "requirements":["CN-TEST-001","CN-TEST-002","CN-TEST-004","CN-TEST-005"],
        "maximum_report_bytes":4194304,
        "adverse_population":["each of nine unit axes changed independently", "unclaimed capture lifetime or replay class added", "realized native case relabeled model or protocol-only", "mandatory residual case replaced with Passed"],
        "oracle":"compare exact closed report to the actor's independently measured immutable unit, full predeclared plan, original native result and retirement",
        "limitations":["report metadata and provenance classification only", "not completeness of any behavioral class", "no replacement of failed original results", "no accepted qualification or ordinary provider readiness"]
    })
}

/// Inspects the complete original report against the opaque actor's source facts.
///
/// # Errors
/// Refuses changed report bytes, unit, classes, policy, original results or
/// case classifications. Missing raw source-unit bodies and contradictory
/// dispositions refuse before producing an inspection body.
pub(super) fn inspect(
    original: &CandidateHarnessResult,
    issued: &IssuedQualification,
) -> Result<OriginalMetadataInspection, QualificationError> {
    issued.reference().verify(issued.bytes())?;
    let mut inspection = inspect_bytes(
        original,
        issued.reference(),
        issued.bytes(),
        issued.objects(),
    )?;
    inspection.counterfactuals = counterfactuals(original, issued)?;
    Ok(inspection)
}

fn inspect_bytes(
    original: &CandidateHarnessResult,
    report: &ContentRef,
    report_bytes: &[u8],
    report_objects: &[(ContentRef, Bytes)],
) -> Result<OriginalMetadataInspection, QualificationError> {
    report.verify(report_bytes)?;
    let claim: QualificationClaim =
        serde_json::from_value(canonical::parse_json(report_bytes, 4 * 1024 * 1024)?)
            .map_err(crucible_node_contract::ContractError::from)?;
    let (unit, criteria) = original
        .qualification_context()
        .ok_or(refused("original source unit absent"))?;
    let classes = BTreeSet::from([
        QualificationClass::BaseProvider,
        QualificationClass::QuantizedTiming,
        QualificationClass::RoleProfile,
    ]);
    if claim.format != "crucible.node-qualification"
        || claim.version != 1
        || claim.unit != unit.identity
        || claim.classes != classes
        || claim.classes != criteria.plan.classes
        || claim.applicability_policy != criteria.reference
        || claim.limitations != criteria.plan.limitations
        || claim.requirements.len() != criteria.plan.requirements.len()
        || claim.catalog != crate::node_qualification::requirement_catalog()?.0
    {
        return Err(refused("report identity or orthogonal classes changed"));
    }
    let mut objects = BTreeMap::new();
    for (reference, bytes) in report_objects {
        reference.verify(bytes.as_slice())?;
        if objects.insert(reference, bytes.as_slice()).is_some() {
            return Err(refused("duplicate original report object"));
        }
    }
    for (reference, bytes) in &unit.objects {
        reference.verify(bytes)?;
    }
    let package = super::package::InstalledPublicReferencePackage::built_in()
        .map_err(|_| refused("actual source package remeasurement refused"))?;
    let implementation = canonical::parse_json(
        unit.objects
            .get(&claim.unit.implementation)
            .ok_or(refused("original implementation unit absent"))?,
        1024 * 1024,
    )?;
    if implementation.get("package")
        != Some(
            &serde_json::to_value(package.identity())
                .map_err(crucible_node_contract::ContractError::from)?,
        )
    {
        return Err(refused("original measured package identity changed"));
    }
    verify_independent_axes(unit)?;
    let mut exact_unit_objects = Vec::with_capacity(9);
    for reference in [
        &claim.unit.implementation,
        &claim.unit.realization,
        &claim.unit.descriptors,
        &claim.unit.contracts,
        &claim.unit.port_profiles,
        &claim.unit.environment,
        &claim.unit.harness,
        &claim.unit.fixtures,
        &claim.unit.specification,
    ] {
        let bytes = unit
            .objects
            .get(reference)
            .ok_or(refused("measured source-unit bytes unavailable"))?;
        exact_unit_objects.push(MetadataObject {
            reference: reference.clone(),
            bytes: Bytes::new(bytes.clone()),
        });
    }

    for (row, (id, criterion)) in claim.requirements.iter().zip(&criteria.plan.requirements) {
        if row.requirement != *id {
            return Err(refused("original requirement population changed"));
        }
        match criterion {
            WitnessCriterion::NotApplicable { reason, .. } => {
                if row.disposition != RequirementDisposition::NotApplicable
                    || row.not_applicable_reason.as_ref() != Some(reason)
                    || !row.cases.is_empty()
                {
                    return Err(refused("trusted exact conditional exclusion changed"));
                }
            }
            WitnessCriterion::Applicable { cases, .. } => {
                if row.not_applicable_reason.is_some()
                    || !row.cases.iter().map(|case| &case.case).eq(cases.iter())
                {
                    return Err(refused("original planned cases changed"));
                }
                for case in &row.cases {
                    let planned = criteria
                        .plan
                        .cases
                        .iter()
                        .find(|planned| planned.id == case.case)
                        .ok_or(refused("unplanned report case"))?;
                    if case.kind != planned.kind
                        || case.classes != planned.classes
                        || case.oracle != planned.oracle
                        || !objects.contains_key(&case.result)
                    {
                        return Err(refused("case provenance classification changed"));
                    }
                    verify_original_result(original, case)?;
                }
                let expected = if row
                    .cases
                    .iter()
                    .any(|case| case.verdict == CaseVerdict::Failed)
                {
                    RequirementDisposition::Failed
                } else if row
                    .cases
                    .iter()
                    .any(|case| case.verdict == CaseVerdict::NotExecuted)
                {
                    RequirementDisposition::NotExecuted
                } else if row
                    .cases
                    .iter()
                    .any(|case| case.verdict == CaseVerdict::Unsupported)
                {
                    RequirementDisposition::Unsupported
                } else {
                    RequirementDisposition::Passed
                };
                if row.disposition != expected {
                    return Err(refused("report hides original nonpassing population"));
                }
            }
        }
    }
    let reviews = [
        ("CN-TEST-001", "exact nine-part independently measured qualification tuple and explicit selected class set"),
        ("CN-TEST-002", "distinct class enumeration: quantized timing and role are selected; exact, repeatability, architectural/live/durable capture, branch and replay are separately unclaimed"),
        ("CN-TEST-004", "every tested implementation/configuration/contract/environment/oracle reference resolves to exact source-measured bytes; original live binding and receipts remain distinct evidence"),
        ("CN-TEST-005", "only original opaque actor-native cases are classified realized_provider; every unresolved source inspection retains its distinct provenance and NotExecuted verdict"),
    ]
    .into_iter()
    .map(|(requirement, property)| MetadataReview {
        requirement,
        property,
        case_kind: CaseKind::SourceInspection,
        limitations: "metadata inspection only; no remaining native behavior, full population acceptance or Ready claim",
    })
    .collect();
    Ok(OriginalMetadataInspection {
        schema: "crucible.reference.original-report-metadata-inspection.v1",
        original_report: report.clone(),
        original_report_bytes: Bytes::new(report_bytes.to_vec()),
        original_native: canonical::content_ref(original.original_bytes(), "application/json")?,
        original_retirement: canonical::content_ref(
            original.retirement_bytes(),
            "application/json",
        )?,
        exact_unit_objects,
        reviews,
        counterfactuals: Vec::new(),
    })
}

fn counterfactuals(
    original: &CandidateHarnessResult,
    issued: &IssuedQualification,
) -> Result<Vec<MetadataCounterfactual>, QualificationError> {
    let value = canonical::parse_json(issued.bytes(), 4 * 1024 * 1024)?;
    if issued
        .bytes()
        .len()
        .checked_mul(14)
        .is_none_or(|bytes| bytes > 64 * 1024 * 1024)
    {
        return Err(refused("predeclared metadata counterfactual byte ceiling"));
    }
    let replacement = canonical::content_ref(
        b"source-owned hostile metadata axis; not a measured implementation",
        "text/plain",
    )?;
    let mut mutations = Vec::with_capacity(14);
    for axis in [
        "implementation",
        "realization",
        "descriptors",
        "contracts",
        "port_profiles",
        "environment",
        "harness",
        "fixtures",
        "specification",
    ] {
        let mut changed = value.clone();
        changed["unit"][axis] = serde_json::to_value(&replacement)
            .map_err(crucible_node_contract::ContractError::from)?;
        mutations.push((
            format!("changed-unit-{axis}"),
            changed,
            "report identity or orthogonal classes changed",
        ));
    }
    for class in ["capture-modeled-durable", "conditional-replay"] {
        let mut changed = value.clone();
        let classes = changed["classes"]
            .as_array_mut()
            .ok_or(refused("original classes unavailable"))?;
        classes.push(serde_json::Value::String(class.into()));
        mutations.push((
            format!("added-unclaimed-{class}"),
            changed,
            "report identity or orthogonal classes changed",
        ));
    }
    for kind in ["model", "independent_protocol"] {
        let mut changed = value.clone();
        let case = changed["requirements"]
            .as_array_mut()
            .ok_or(refused("original requirements absent"))?
            .iter_mut()
            .filter_map(|row| row["cases"].as_array_mut())
            .flatten()
            .find(|case| case["kind"] == "realized_provider")
            .ok_or(refused("original native case absent"))?;
        case["kind"] = serde_json::Value::String(kind.into());
        mutations.push((
            format!("native-relabeled-{kind}"),
            changed,
            "case provenance classification changed",
        ));
    }
    let mut changed = value;
    let case = changed["requirements"]
        .as_array_mut()
        .ok_or(refused("original requirements absent"))?
        .iter_mut()
        .filter_map(|row| row["cases"].as_array_mut())
        .flatten()
        .find(|case| case["verdict"] == "not_executed")
        .ok_or(refused("original residual case absent"))?;
    case["verdict"] = serde_json::Value::String("passed".into());
    mutations.push((
        "unexecuted-review-replaced".into(),
        changed,
        "unexecuted review represented as native success",
    ));

    let mut results = Vec::with_capacity(14);
    for (case, changed, expected) in mutations {
        let bytes = canonical::canonical_json(&changed)?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        match inspect_bytes(original, &reference, &bytes, issued.objects()) {
            Err(QualificationError::Refused(reason)) if reason == expected => {
                results.push(MetadataCounterfactual {
                    case,
                    observation_kind: "inert rehashed report mutation; not a provider request",
                    changed_report: reference,
                    changed_report_bytes: Bytes::new(bytes),
                    original_refusal: reason,
                });
            }
            _ => return Err(refused("metadata mutation did not reach its exact refusal")),
        }
    }
    Ok(results)
}

fn verify_original_result(
    original: &CandidateHarnessResult,
    case: &crate::node_qualification::CaseEvidence,
) -> Result<(), QualificationError> {
    let original_bytes = match case.case.as_str() {
        "reference/native-complete-world-and-windows" => Some(original.original_bytes()),
        "reference/native-original-custody-retirement" => Some(original.retirement_bytes()),
        _ => None,
    };
    if let Some(bytes) = original_bytes {
        let expected = if case.case == "reference/native-complete-world-and-windows" {
            if original.succeeded() {
                CaseVerdict::Passed
            } else {
                CaseVerdict::Failed
            }
        } else {
            let retirement = canonical::parse_json(bytes, 1024 * 1024)?;
            if retirement["reclaimed_original_peers"] == 2
                && retirement["world_reservations"] == 0
                && retirement["original_scopes"]
                    .as_array()
                    .is_some_and(|owners| owners.len() == 2)
            {
                CaseVerdict::Passed
            } else {
                CaseVerdict::Failed
            }
        };
        if case.kind != CaseKind::RealizedProvider
            || case.verdict != expected
            || case.result != canonical::content_ref(bytes, "application/json")?
        {
            return Err(refused("claimed realized case differs from original actor"));
        }
    } else if case.kind != CaseKind::SourceInspection || case.verdict != CaseVerdict::NotExecuted {
        return Err(refused("unexecuted review represented as native success"));
    }
    Ok(())
}

fn verify_independent_axes(
    unit: &super::unit::SemanticQualificationUnit,
) -> Result<(), QualificationError> {
    let bytes = unit
        .objects
        .get(&unit.identity.realization)
        .ok_or(refused("original realized unit unavailable"))?;
    let realization = canonical::parse_json(bytes, 8 * 1024 * 1024)?;
    let nodes = realization["nodes"]
        .as_array()
        .ok_or(refused("original realized node roster absent"))?;
    if nodes.len() != 2 {
        return Err(refused("original realized roster changed"));
    }
    for node in nodes {
        let guarantees: GuaranteeProfile = serde_json::from_value(node["guarantees"].clone())
            .map_err(crucible_node_contract::ContractError::from)?;
        let operating: OperatingContract =
            serde_json::from_value(node["operating_contract"].clone())
                .map_err(crucible_node_contract::ContractError::from)?;
        let descriptor: NodeDescriptor = serde_json::from_value(node["descriptor"].clone())
            .map_err(crucible_node_contract::ContractError::from)?;
        if operating.mode != OperatingMode::Quantized
            || guarantees.repeatability != Repeatability::Nondeterministic
            || guarantees.capture_scope != CaptureScope::None
            || guarantees.continuation != Continuation::Unsupported
            || guarantees.durable_restart
            || guarantees.isolated_fork
            || guarantees.conditional_replay
            || descriptor.roles.is_empty()
        {
            return Err(refused(
                "reported independent guarantee axes differ from actual source",
            ));
        }
    }
    Ok(())
}

fn refused(reason: &'static str) -> QualificationError {
    QualificationError::Refused(reason)
}

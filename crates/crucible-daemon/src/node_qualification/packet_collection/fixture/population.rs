//! Freezes every normative obligation and two distinct original runtime cases.
//!
//! Every RFC obligation remains required. The two packet observations supplement
//! their own still-unexecuted normative rows; they cannot complete the catalog.

use std::collections::{BTreeMap, BTreeSet};

use crucible::node_contract::{ExactBoundaryPolicy, OperationRequest};
use crucible_node_contract::{ContentRef, Id, Phase, Position, U64, canonical};
use serde::Serialize;

use super::super::{PacketNativeCase, scope};
use super::{FixtureBodies, PacketFixtureMeasurements, refused};
use crate::node_qualification::{
    CaseKind, PlannedWitnessCase, QualificationClass, QualificationError, QualificationUnit,
    WitnessCriterion, WitnessPlan, normative_specification, requirement_catalog,
};

pub(super) const BEFORE: &str = "packet-original-before-ack";
pub(super) const AFTER: &str = "packet-original-after-ack";
pub(super) const LIMITATIONS: &[u8] = b"Collection only: all 382 original normative requirements remain required and NotExecuted until independently observed. Two fixed output-only Exact/Nondeterministic native observations cannot qualify an ordinary class, Clock, Compute, preservation, replay or input support. Original source, native process, UDP receiver and durable stores remain mandatory independent conjunctions.";

pub(super) struct Population {
    pub(super) plan: WitnessPlan,
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) cases: Vec<PacketNativeCase>,
    pub(super) bodies: FixtureBodies,
    pub(super) kernel: String,
}

pub(super) fn classes() -> BTreeSet<QualificationClass> {
    BTreeSet::from([
        QualificationClass::BaseProvider,
        QualificationClass::ExactTiming,
        QualificationClass::RoleProfile,
    ])
}

pub(super) fn retain(
    bodies: &mut FixtureBodies,
    value: &impl Serialize,
) -> Result<ContentRef, QualificationError> {
    // All prospective JSON is counted before Value/canonical ownership.
    let retained = bodies.values().try_fold(0usize, |total, bytes| {
        total.checked_add(bytes.len()).ok_or_else(refused)
    })?;
    let remaining = (8usize * 1024 * 1024)
        .checked_sub(retained)
        .ok_or_else(refused)?;
    if bodies.len() >= 1024 {
        return Err(refused());
    }
    scope::encoded_size(value, remaining.min(1024 * 1024))?;
    let bytes = canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    retain_bytes(bodies, bytes, "application/json")
}

pub(super) fn retain_bytes(
    bodies: &mut FixtureBodies,
    bytes: Vec<u8>,
    media: &str,
) -> Result<ContentRef, QualificationError> {
    let total = bodies.values().try_fold(bytes.len(), |total, bytes| {
        total.checked_add(bytes.len()).ok_or_else(refused)
    })?;
    if bodies.len() >= 1024 || total > 8 * 1024 * 1024 {
        return Err(refused());
    }
    let reference = canonical::content_ref(&bytes, media)?;
    if let Some(prior) = bodies.get(&reference) {
        if *prior != bytes {
            return Err(refused());
        }
    } else {
        bodies.insert(reference.clone(), bytes);
    }
    Ok(reference)
}

pub(super) fn build(
    selection: &crucible::node_adapters::cnp::CnpSemanticInstallation,
    measurements: &PacketFixtureMeasurements,
    program: &crucible_node_provider::reference_packet::PacketProgramDefinition,
    operation: &Id,
    horizon: U64,
) -> Result<Population, QualificationError> {
    let mut bodies = BTreeMap::new();
    let (specification, original) = normative_specification()?;
    if retain_bytes(&mut bodies, original, "application/json")? != specification {
        return Err(refused());
    }
    let (catalog, ids) = requirement_catalog()?;
    if ids.len() != 382 {
        return Err(refused());
    }
    let catalog_bytes = format!("{}\n", ids.join("\n")).into_bytes();
    if retain_bytes(&mut bodies, catalog_bytes, "text/plain")? != catalog {
        return Err(refused());
    }
    let implementation = retain(
        &mut bodies,
        &(&selection.provider.implementation, measurements),
    )?;
    let realization = retain(
        &mut bodies,
        &(
            &selection.profile,
            &selection.binding.compatibility,
            &selection.capabilities,
            &selection.guarantees,
            &selection.owner,
            &selection.realize.resource_limits,
            &selection.world_binding_hash,
        ),
    )?;
    let descriptors = retain(&mut bodies, &selection.descriptor)?;
    let contracts = retain(
        &mut bodies,
        &(
            &selection.binding.compatibility.operating_contract,
            &selection.exact_facet,
            &selection.receipt_schema,
            selection.maximum_operations,
            selection.maximum_result_bytes,
            selection.maximum_authorization_bytes,
            selection.maximum_semantic_bytes,
        ),
    )?;
    let port_profiles = retain(
        &mut bodies,
        &(&selection.descriptor.roles, &selection.descriptor.ports),
    )?;
    let kernel = super::measurement::kernel()?;
    let environment = retain(
        &mut bodies,
        &(
            std::env::consts::ARCH,
            std::env::consts::OS,
            kernel.as_str(),
            &selection.realize.resource_limits,
        ),
    )?;
    let harness = retain(&mut bodies, &(&measurements.host, &measurements.sources))?;
    let fixtures = retain(
        &mut bodies,
        &(program, operation, horizon, BEFORE, AFTER, &catalog),
    )?;
    let unit = QualificationUnit {
        implementation,
        realization,
        descriptors,
        contracts,
        port_profiles,
        environment,
        harness,
        fixtures,
        specification,
    };
    let limitations = retain_bytes(&mut bodies, LIMITATIONS.to_vec(), "text/plain")?;
    let classes = classes();
    let (mut cases, requirements) = normative_rows(&mut bodies, &unit, &catalog, &ids)?;
    let request = OperationRequest::ExactRun {
        start: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        limit: Position::new(horizon, U64::new(0), Phase::BoundaryControl),
        boundary_policy: ExactBoundaryPolicy::HorizonPark,
    };
    let mut native = Vec::new();
    native.try_reserve_exact(2).map_err(|_| refused())?;
    for (case, acknowledged) in [(BEFORE, false), (AFTER, true)] {
        let oracle = retain(
            &mut bodies,
            &(
                "packet-whole-original-template.v1",
                case,
                &selection.descriptor.id,
                operation,
                &request,
                program,
                acknowledged,
                "Exact full source-native receipt AND independently owned UDP observations before common report inspection",
            ),
        )?;
        cases.push(PlannedWitnessCase {
            id: case.into(),
            kind: CaseKind::RealizedProvider,
            classes: classes.clone(),
            oracle: oracle.clone(),
        });
        native.push(PacketNativeCase {
            case: case.into(),
            oracle,
            operation: operation.clone(),
            request: request.clone(),
            acknowledged,
        });
    }
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    let plan = WitnessPlan {
        schema: "crucible.node-witness-plan.v1".into(),
        unit,
        classes,
        requirements,
        cases,
        limitations,
    };
    scope::encoded_size(&plan, 1024 * 1024)?;
    let bytes = canonical::canonical_json(
        &serde_json::to_value(&plan).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    let reference = retain_bytes(&mut bodies, bytes.clone(), "application/json")?;
    Ok(Population {
        plan,
        reference,
        bytes,
        cases: native,
        bodies,
        kernel,
    })
}

fn normative_rows(
    bodies: &mut FixtureBodies,
    unit: &QualificationUnit,
    catalog: &ContentRef,
    ids: &[&str],
) -> Result<(Vec<PlannedWitnessCase>, BTreeMap<String, WitnessCriterion>), QualificationError> {
    let (original_catalog, original_ids) = requirement_catalog()?;
    if ids != original_ids.as_slice() || catalog != &original_catalog || ids.len() != 382 {
        return Err(refused());
    }
    let mut cases = Vec::new();
    cases.try_reserve_exact(384).map_err(|_| refused())?;
    let mut requirements = BTreeMap::new();
    for &id in ids {
        let case = format!("unexecuted-original-{id}");
        let criterion = retain(
            bodies,
            &(
                "packet-full-obligation.v1",
                id,
                &catalog,
                &unit.specification,
                &unit.implementation,
                "required-original-native-or-inspection-evidence",
            ),
        )?;
        let oracle = retain(
            bodies,
            &(
                "packet-unexecuted-oracle.v1",
                id,
                &criterion,
                "No observation has executed; this row cannot be authenticated as Passed.",
            ),
        )?;
        cases.push(PlannedWitnessCase {
            id: case.clone(),
            kind: CaseKind::RealizedProvider,
            classes: classes(),
            oracle,
        });
        let mut required = vec![case];
        if id == "CN-TEST-025" || id == "CN-TEST-038" {
            required.extend([BEFORE.to_owned(), AFTER.to_owned()]);
            required.sort();
        }
        requirements.insert(
            id.into(),
            WitnessCriterion::Applicable {
                cases: required,
                criterion,
            },
        );
    }
    Ok((cases, requirements))
}

#[cfg(test)]
#[path = "population/tests.rs"]
mod tests;

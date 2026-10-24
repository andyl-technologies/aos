//! Retains all original obligations and distinct connected cases as unexecuted data.
//!
//! An independently installed authority must bind the complete measured unit.
//! This builder supplies no class acceptance, operation admission or native
//! observation. It never borrows the disconnected scene's 54 output templates.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_format::{ContentRef, canonical};
use serde::Serialize;

use crate::node_qualification::{
    CaseKind, PlannedWitnessCase, QualificationClass, QualificationUnit, WitnessCriterion,
    WitnessPlan, normative_specification, requirement_catalog,
};

use super::{PacketConnectedCaseKind, PacketConnectedSchedule, QualificationError, refused};

/// Borrows the complete measured collecting unit and its distinct source schedule.
///
/// These are data only. The installed authority must independently reconstruct
/// the same unit from original source/host ownership before enrolling this plan.
pub struct PacketConnectedPopulationRequest<'a> {
    /// Retains the complete independently measured source/host/world identity.
    pub unit: QualificationUnit,
    /// Borrows all original grants and connected witnesses before native launch.
    pub schedule: &'a PacketConnectedSchedule,
    /// Borrows every complete body referenced by the selected unit.
    pub content: &'a BTreeMap<ContentRef, Vec<u8>>,
}

/// Retains the complete Refused witness population without an authority token.
pub struct PacketConnectedWitnessPopulation {
    pub(super) plan: WitnessPlan,
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) bodies: BTreeMap<ContentRef, Vec<u8>>,
}

impl PacketConnectedWitnessPopulation {
    /// Freezes every original requirement and every declared connected witness.
    ///
    /// The complete normative catalog is always applicable. Distinct source
    /// witnesses supplement its fixed obligations and cannot authenticate Passed
    /// merely because they are selected or because a native packet was emitted.
    ///
    /// # Errors
    /// Refuses missing/changed unit bodies, wrong specification, incomplete
    /// catalog, invalid source schedule or finite canonical allocation ceilings.
    pub fn build(
        request: PacketConnectedPopulationRequest<'_>,
    ) -> Result<Self, QualificationError> {
        request.schedule.validate()?;
        super::super::scope::encoded_size(&request.unit, 65_536)?;
        if request.content.len() > 128 {
            return Err(refused());
        }
        let mut bodies = BTreeMap::new();
        let mut extent = 0usize;
        for (reference, bytes) in request.content {
            extent = extent.checked_add(bytes.len()).ok_or_else(refused)?;
            if bytes.len() > 1024 * 1024 || extent > 2 * 1024 * 1024 {
                return Err(refused());
            }
            reference.verify(bytes)?;
            bodies.insert(reference.clone(), bytes.clone());
        }
        for reference in [
            &request.unit.implementation,
            &request.unit.realization,
            &request.unit.descriptors,
            &request.unit.contracts,
            &request.unit.port_profiles,
            &request.unit.environment,
            &request.unit.harness,
            &request.unit.fixtures,
        ] {
            if !bodies.contains_key(reference) {
                return Err(refused());
            }
        }
        let (specification, specification_bytes) = normative_specification()?;
        if request.unit.specification != specification
            || retain_bytes(&mut bodies, specification_bytes, "application/json")? != specification
        {
            return Err(refused());
        }
        let (catalog, ids) = requirement_catalog()?;
        if ids.len() != 382
            || ids.iter().collect::<BTreeSet<_>>().len() != 382
            || retain_bytes(
                &mut bodies,
                format!("{}\n", ids.join("\n")).into_bytes(),
                "text/plain",
            )? != catalog
        {
            return Err(refused());
        }
        let classes = BTreeSet::from([
            QualificationClass::BaseProvider,
            QualificationClass::ExactTiming,
            QualificationClass::RoleProfile,
        ]);
        let mut cases = Vec::new();
        cases
            .try_reserve_exact(382 + request.schedule.cases.len())
            .map_err(|_| refused())?;
        let mut requirements = BTreeMap::new();
        for id in ids {
            let mut required = vec![format!("unexecuted-original-{id}")];
            required.extend(
                request
                    .schedule
                    .cases
                    .iter()
                    .filter(|case| supplemental_obligations(case.kind).contains(&id))
                    .map(|case| case.id.clone()),
            );
            required.sort();

            let criterion = retain(
                &mut bodies,
                &(
                    "packet-connected-original-obligation.v4",
                    id,
                    &catalog,
                    &request.unit,
                    &required,
                    "required original normative evidence; absent evidence remains NotExecuted",
                ),
            )?;
            let oracle = retain(
                &mut bodies,
                &(
                    "packet-connected-unexecuted-original.v4",
                    id,
                    &criterion,
                    "no supplemental packet control can substitute for this original obligation",
                ),
            )?;
            let case = format!("unexecuted-original-{id}");
            cases.push(PlannedWitnessCase {
                id: case.clone(),
                kind: CaseKind::RealizedProvider,
                classes: classes.clone(),
                oracle,
            });
            requirements.insert(
                id.into(),
                WitnessCriterion::Applicable {
                    cases: required,
                    criterion,
                },
            );
        }
        for original in &request.schedule.cases {
            let oracle = retain(
                &mut bodies,
                &(
                    "packet-connected-original-witness.v4",
                    original,
                    &request.unit,
                    request.schedule,
                    "actual same-runtime token, original source journal, independent effect/custody oracle and durable root required; initially NotExecuted",
                ),
            )?;
            cases.push(PlannedWitnessCase {
                id: original.id.clone(),
                kind: CaseKind::RealizedProvider,
                classes: classes.clone(),
                oracle,
            });
        }
        cases.sort_by(|a, b| a.id.cmp(&b.id));
        if cases.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(refused());
        }
        let limitations = retain_bytes(
            &mut bodies,
            b"Connected collection only: all 382 original normative requirements are required and NotExecuted absent their independent evidence. Connected Stage/ACK/Commit/Delivery/Reaction/Publication, frontier refusal, delay closure, retirement and durable-root cases are separate supplemental witnesses. This data issues no native acceptance, Node/class acceptance, Ready, Clock, Compute, checkpoint, replay or full RFC qualification.".to_vec(),
            "text/plain",
        )?;
        let plan = WitnessPlan {
            schema: "crucible.node-witness-plan.v1".into(),
            unit: request.unit,
            classes,
            requirements,
            cases,
            limitations,
        };
        super::super::scope::encoded_size(&plan, 1024 * 1024)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(&plan).map_err(crucible_node_format::ContractError::from)?,
        )?;
        let reference = retain_bytes(&mut bodies, bytes.clone(), "application/json")?;
        Ok(Self {
            plan,
            reference,
            bytes,
            bodies,
        })
    }

    /// Borrows the complete original plan; unknown cases remain explicit.
    pub fn plan(&self) -> &WitnessPlan {
        &self.plan
    }

    /// Borrows complete canonical plan bytes without creating authority.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the complete immutable plan identity.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows all exact unit, criterion and source-witness body objects.
    pub fn bodies(&self) -> &BTreeMap<ContentRef, Vec<u8>> {
        &self.bodies
    }
}

// These associations add independent source witnesses as conjuncts. They never
// discharge the required original case, or imply that a narrow packet control
// covers the complete normative obligation. Retirement means original outcome
// custody, not process exit; DurableRoot means outcome acceptance, not capture.
fn supplemental_obligations(kind: PacketConnectedCaseKind) -> &'static [&'static str] {
    use PacketConnectedCaseKind::*;

    match kind {
        Stage | InputAcknowledgement => &["CN-NODE-23", "CN-IPC-22"],
        Commit => &["CN-NODE-24", "CN-IPC-22"],
        Delivery => &["CN-NODE-23", "CN-TIME-34"],
        Reaction => &["CN-TIME-9", "CN-TIME-18"],
        Publication => &["CN-TIME-11", "CN-TIME-34"],
        BeforeRetirement | AfterRetirement => &["CN-NODE-44", "CN-IPC-18"],
        SlowProducerRefusal => &["CN-TIME-12", "CN-TIME-13"],
        ZeroDelayClosure => &["CN-TIME-18", "CN-TEST-036"],
        PositiveDelayCoordinate => &["CN-TIME-14", "CN-TIME-34"],
        DurableRoot => &["CN-TIME-11", "CN-TEST-038"],
    }
}

fn retain<T: Serialize>(
    bodies: &mut BTreeMap<ContentRef, Vec<u8>>,
    value: &T,
) -> Result<ContentRef, QualificationError> {
    super::super::scope::encoded_size(value, 1024 * 1024)?;
    let bytes = canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?,
    )?;
    retain_bytes(bodies, bytes, "application/json")
}

fn retain_bytes(
    bodies: &mut BTreeMap<ContentRef, Vec<u8>>,
    bytes: Vec<u8>,
    media_type: &str,
) -> Result<ContentRef, QualificationError> {
    if bytes.len() > 1024 * 1024 || bodies.len() >= 2048 {
        return Err(refused());
    }
    let total = bodies.values().try_fold(bytes.len(), |sum, body| {
        sum.checked_add(body.len()).ok_or_else(refused)
    })?;
    if total > 16 * 1024 * 1024 {
        return Err(refused());
    }
    let reference = canonical::content_ref(&bytes, media_type)?;
    if let Some(original) = bodies.get(&reference) {
        if original != &bytes {
            return Err(refused());
        }
    } else {
        bodies.insert(reference.clone(), bytes);
    }
    Ok(reference)
}

#[cfg(test)]
#[path = "population/tests.rs"]
mod tests;

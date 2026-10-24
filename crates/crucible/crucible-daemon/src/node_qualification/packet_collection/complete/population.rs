//! Retains all original obligations and complete preservation classes as unexecuted data.
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

use super::{QualificationError, refused};

/// Borrows the complete measured collecting unit and its distinct complete source scope.
///
/// These are data only. The installed authority must independently reconstruct
/// the same unit from original source/host ownership before enrolling this plan.
pub struct PacketCompletePopulationRequest<'a> {
    /// Retains the complete independently measured source/host/world identity.
    pub unit: QualificationUnit,
    /// Borrows every complete body referenced by the selected unit.
    pub content: &'a BTreeMap<ContentRef, Vec<u8>>,
}

/// Retains the complete Refused witness population without an authority token.
pub struct PacketCompleteWitnessPopulation {
    pub(super) plan: WitnessPlan,
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    pub(super) bodies: BTreeMap<ContentRef, Vec<u8>>,
}

impl PacketCompleteWitnessPopulation {
    /// Freezes every original requirement with every original obligation still unexecuted.
    ///
    /// The complete normative catalog remains applicable. Every case starts
    /// without execution evidence, including both preservation classes.
    ///
    /// # Errors
    /// Refuses missing/changed unit bodies, wrong specification, incomplete
    /// catalog or exhausted finite canonical allocation ceilings.
    pub fn build(request: PacketCompletePopulationRequest<'_>) -> Result<Self, QualificationError> {
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
            QualificationClass::CaptureModeledLive,
            QualificationClass::CaptureModeledDurable,
        ]);
        let mut cases = Vec::new();
        cases.try_reserve_exact(382).map_err(|_| refused())?;
        let mut requirements = BTreeMap::new();
        for id in ids {
            let required = vec![format!("unexecuted-original-{id}")];

            let criterion = retain(
                &mut bodies,
                &(
                    "packet-complete-original-obligation.v5",
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
                    "packet-complete-unexecuted-original.v5",
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
        cases.sort_by(|a, b| a.id.cmp(&b.id));
        if cases.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(refused());
        }
        let limitations = retain_bytes(
            &mut bodies,
            b"Complete packet preparation collection only: all 382 original normative obligations remain required and NotExecuted. Preservation classes are required declarations, not passing evidence. This plan grants no Capture, Arm, operation, native observation, class acceptance or readiness.".to_vec(),
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

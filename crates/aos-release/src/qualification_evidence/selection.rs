//! Obligation selection for one destination and hold point.
//!
//! Requirements and claims are selected from the gates frozen in a planned
//! destination, so the profile, change scope, and any accepted override are
//! applied exactly as planned.

use std::collections::BTreeMap;

use anyhow::{Result, bail};

use crate::digest::Sha256Digest;
use crate::evidence::GateRequirement;
use crate::plan::ReleasePlan;
use crate::qualification::claims::QualificationClaim;
use crate::qualification::limits::EXERCISE_MAX_AGE_SECONDS;
use crate::qualification::{
    ChangeScope, EffectiveProfile, QualificationContract, QualificationPhase,
    QualificationRequirement, QualificationScope,
};

/// Identifies transition obligations that require a frozen prior release.
pub(super) fn requires_predecessor(requirement_id: &str) -> bool {
    matches!(
        requirement_id,
        "image-update-recovery" | super::NATIVE_ADAPTER_MATRIX_REQUIREMENT
    )
}

/// Obligations, gate identities, and time bounds for one case expansion.
pub(super) struct Selection<'a> {
    /// Shared contract embedded in the plan.
    pub contract: &'a QualificationContract,
    /// Release- and package-scope requirements for the phase, in contract order.
    pub requirements: Vec<&'a QualificationRequirement>,
    /// Target claims for the phase, in contract order.
    pub claims: Vec<&'a QualificationClaim>,
    /// Frozen gate policy digests keyed by policy id.
    pub gates: BTreeMap<String, Sha256Digest>,
    /// Observation window for A3 claims and `rollout-observation`.
    pub soak_seconds: u64,
    /// Maximum age of non-rollout observations at admission.
    pub exercise_max_age_seconds: u64,
    /// Change scope restricting package cells, for change-scoped profiles.
    pub package_scope: Option<&'a ChangeScope>,
}

impl Selection<'_> {
    /// Returns the frozen policy digest of one requirement or claim gate.
    ///
    /// # Errors
    /// Returns an error when the selection has no gate with that id.
    pub fn policy_digest(&self, policy_id: &str) -> Result<Sha256Digest> {
        self.gates
            .get(policy_id)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("missing planned requirement {policy_id}"))
    }
}

/// Selects the obligations of `destination` at `phase`.
///
/// `destination = None` selects the union of every planned destination, or
/// for a plan without destinations (a qualification snapshot) every
/// requirement and claim of the contract. `effective`, when supplied, must
/// equal the soak and rings the plan froze for the destination; the plan is
/// the authority, and the argument only cross-checks a separately verified
/// override.
/// Non-publishable qualification snapshots omit transition obligations and
/// their dependent claims because they have no predecessor to exercise.
pub(super) fn select<'a>(
    plan: &'a ReleasePlan,
    destination: Option<&str>,
    phase: QualificationPhase,
    effective: Option<&EffectiveProfile>,
) -> Result<Selection<'a>> {
    let mut selection = select_obligations(plan, destination, phase, effective)?;

    if plan.is_qualification_snapshot() {
        selection
            .requirements
            .retain(|requirement| !requires_predecessor(&requirement.id));
        selection.claims.retain(|claim| {
            !claim
                .requirements
                .iter()
                .any(|requirement| requires_predecessor(requirement))
        });
    }
    Ok(selection)
}

fn select_obligations<'a>(
    plan: &'a ReleasePlan,
    destination: Option<&str>,
    phase: QualificationPhase,
    effective: Option<&EffectiveProfile>,
) -> Result<Selection<'a>> {
    let contract = &plan.qualification;
    let production =
        crate::registry::registry_policy(&plan.registry)?.requires_production_assurance();
    let (gates, soak_seconds, package_scope) = match destination {
        Some(name) => {
            let planned = plan.destination(name)?;
            if effective.is_some_and(|effective| *effective != planned.effective()) {
                bail!("effective soak and rings differ from the plan's destination {name}");
            }
            let profile = contract.profile(&planned.profile)?;
            let scope = if profile.change_scoped {
                Some(plan.change_scope.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "change-scoped destination {name} lacks a recorded change scope"
                    )
                })?)
            } else {
                None
            };
            (gate_map(&planned.gates)?, planned.soak_seconds, scope)
        }
        None if effective.is_some() => {
            bail!("an effective profile applies to exactly one destination")
        }
        None if plan.destinations.is_empty() => {
            let mut gates = Vec::new();
            for requirement in contract
                .requirements
                .iter()
                .filter(|requirement| !requirement.production_only || production)
            {
                gates.push(contract.requirement_gate(requirement)?);
            }
            for claim in &contract.claims {
                gates.push(contract.claim_gate(claim)?);
            }
            let soak = contract
                .profiles
                .iter()
                .map(|profile| profile.soak_seconds)
                .max()
                .unwrap_or(0);
            (gate_map(&gates)?, soak, None)
        }
        None => {
            let gates: Vec<_> = plan.all_gates().into_iter().collect();
            let soak = plan
                .destinations
                .iter()
                .map(|destination| destination.soak_seconds)
                .max()
                .unwrap_or(0);
            (gate_map(&gates)?, soak, None)
        }
    };

    let requirements = contract
        .requirements
        .iter()
        .filter(|requirement| requirement.phase == phase)
        .filter(|requirement| {
            matches!(
                requirement.scope,
                QualificationScope::Release | QualificationScope::Packages
            )
        })
        .filter(|requirement| gates.contains_key(&requirement.id))
        .collect();
    let claims = contract
        .claims
        .iter()
        .filter(|claim| claim.phase == phase)
        .filter(|claim| gates.contains_key(&format!("claim-{}", claim.id)))
        .collect();
    Ok(Selection {
        contract,
        requirements,
        claims,
        gates,
        soak_seconds,
        exercise_max_age_seconds: EXERCISE_MAX_AGE_SECONDS,
        package_scope,
    })
}

fn gate_map(gates: &[GateRequirement]) -> Result<BTreeMap<String, Sha256Digest>> {
    let mut map = BTreeMap::new();
    for gate in gates {
        if map
            .insert(gate.policy_id.clone(), gate.policy_digest)
            .is_some_and(|previous| previous != gate.policy_digest)
        {
            bail!("gate {} is bound to conflicting policies", gate.policy_id);
        }
    }
    Ok(map)
}

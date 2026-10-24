//! Regenerates ordinary host bindings from their retained original acceptance.
//!
//! Every participant is checked through the installed policy. The only native
//! profile transformation is the compiled public Clock family regenerated from
//! the same raw singleton; it is never inferred from report JSON. Other native
//! families keep their full source descriptor and compatibility fields. All
//! future bindings add only their actual authenticated original report reference.

use std::collections::{BTreeMap, BTreeSet};

use crucible_engine::node_admission::{AdmissionEvidence, QualificationClaim};
use crucible_node_format::{BindingCompatibility, ContentRef, Id};

use super::*;
use crate::node_observed_executor::factory::{
    InstalledIoArtifact, InstalledNodeKind, InstalledNodeSelection, profile,
};
use crate::node_scenario::{MAX_NODE_SCENARIO_BYTES, NodeScenario, ScenarioContent};

impl InstalledNodeCatalog {
    pub(in crate::node_observed_executor::factory) fn project_ordinary_accepted_world(
        &self,
        selections: &[InstalledNodeSelection],
        mut scenario: NodeScenario,
        artifacts: &BTreeMap<String, InstalledIoArtifact>,
    ) -> Result<(NodeScenario, BTreeSet<Id>), NodeObservedError> {
        let Some(installed) = &self.behavioral_acceptance else {
            return Ok((scenario, BTreeSet::new()));
        };
        if selections.len() != scenario.compatibility.len()
            || selections.len() != scenario.descriptors.len()
        {
            return Err(refused("ordinary accepted source roster differs"));
        }
        let source_scenario = scenario.world.scenario_ref.clone();
        let mut public_clock_nodes = BTreeSet::new();
        let mut original_reports = BTreeMap::new();
        let mut changed = false;
        let evidence = BehavioralAdmissionEvidence::new(
            &PreallocationCheck,
            installed.policy.as_ref(),
            installed.limits,
        );
        for selected in selections {
            let binding_index = scenario
                .compatibility
                .iter()
                .position(|binding| binding.node_id == selected.node)
                .ok_or_else(|| refused("ordinary accepted source binding absent"))?;
            let descriptor_index = scenario
                .descriptors
                .iter()
                .position(|descriptor| descriptor.id == selected.node)
                .ok_or_else(|| refused("ordinary accepted source descriptor absent"))?;
            let scope = installed
                .policy
                .scope_for_node(&selected.node)
                .map_err(|error| refused(&error.to_string()))?;
            if scope.original_bytes.len() > installed.limits.qualification.maximum_claim_bytes {
                return Err(refused(
                    "ordinary accepted original exceeds installed report limit",
                ));
            }
            // Reauthenticate the retained Accepted original and its full current
            // source before borrowing any report body into the ordinary world.
            evidence
                .qualify(QualificationClaim::Node {
                    binding: scope.binding,
                    binding_hash: &scope.binding.identity()?,
                    qualification_refs: &scope.binding.qualification_refs,
                })
                .map_err(|error| refused(&error.to_string()))?;
            scope.original_claim.verify(scope.original_bytes)?;

            let mut original = scenario.compatibility[binding_index].clone();
            if matches!(selected.kind, InstalledNodeKind::HostClock)
                && selected.node.as_str() == "clock"
            {
                let raw = profile::build_world(
                    std::slice::from_ref(selected),
                    &self.host_identity,
                    &self.device_identity,
                    artifacts,
                )?
                .scenario;
                let public = super::super::normal_clock::profile::build(&raw)?;
                if scope.binding
                    == &with_original_report(&public.compatibility[0], scope.original_claim)?
                {
                    let descriptor = &scenario.descriptors[descriptor_index];
                    if (original != raw.compatibility[0] || descriptor != &raw.descriptors[0])
                        && (original != public.compatibility[0]
                            || descriptor != &public.descriptors[0])
                    {
                        return Err(refused(
                            "ordinary public Clock changed its actual raw source",
                        ));
                    }
                    scenario.descriptors[descriptor_index] = public.descriptors[0].clone();
                    original = public.compatibility[0].clone();
                    for body in &public.content {
                        retain_body(&mut scenario, &body.reference, &body.bytes)?;
                    }
                    public_clock_nodes.insert(selected.node.clone());
                }
            }
            let expected = with_original_report(&original, scope.original_claim)?;
            authenticate_original_report_binding(&original, scope.binding, scope.original_claim)?;
            if scope.required_classes != super::required_classes(&scenario, &original)? {
                return Err(refused(
                    "ordinary accepted binding or complete source classes differ",
                ));
            }
            changed |= scenario.compatibility[binding_index] != expected;
            scenario.compatibility[binding_index] = expected;
            retain_body(&mut scenario, scope.original_claim, scope.original_bytes)?;
            original_reports.insert(selected.node.clone(), scope.original_claim.clone());
        }
        if changed {
            for participant in &mut scenario.world.node_bindings {
                participant.binding_hash = scenario
                    .compatibility
                    .iter()
                    .find(|binding| binding.node_id == participant.node_id)
                    .ok_or_else(|| refused("ordinary accepted world participant absent"))?
                    .identity()?;
            }
            for owner in &mut scenario.owners {
                for participant in &mut owner.node_bindings {
                    participant.binding_hash = scenario
                        .compatibility
                        .iter()
                        .find(|binding| binding.node_id == participant.node_id)
                        .ok_or_else(|| refused("ordinary accepted owner participant absent"))?
                        .identity()?;
                }
            }
            let bytes = canonical::canonical_json(&serde_json::json!({
                "schema":"crucible.original-accepted-host-world/1", "source_scenario":source_scenario,
                "descriptors":scenario.descriptors,"compatibility":scenario.compatibility,"owners":scenario.owners,
                "original_reports":original_reports,
            }))?;
            let reference = canonical::content_ref(&bytes, "application/json")?;
            retain_body(&mut scenario, &reference, &bytes)?;
            scenario.world.scenario_ref = reference;
        }
        scenario.content.sort_by(|left, right| {
            (&left.reference.hash.domain, &left.reference.hash.digest)
                .cmp(&(&right.reference.hash.domain, &right.reference.hash.digest))
        });
        scenario.canonical_bytes()?;
        // The preallocation gate is repeated after all nodes and the complete
        // owner map have been regenerated. Native admission repeats it again.
        self.preflight_behavioral_acceptance(selections, &scenario)?;
        Ok((scenario, public_clock_nodes))
    }
}

fn with_original_report(
    source: &BindingCompatibility,
    report: &ContentRef,
) -> Result<BindingCompatibility, NodeObservedError> {
    let mut selected = source.clone();
    if !selected.qualification_refs.contains(report) {
        selected
            .qualification_refs
            .try_reserve_exact(1)
            .map_err(|_| refused("ordinary accepted report roster allocation"))?;
        selected.qualification_refs.push(report.clone());
        selected.qualification_refs.sort_by(|left, right| {
            (&left.hash.domain, &left.hash.digest).cmp(&(&right.hash.domain, &right.hash.digest))
        });
    }
    Ok(selected)
}

fn retain_body(
    scenario: &mut NodeScenario,
    reference: &ContentRef,
    bytes: &[u8],
) -> Result<(), NodeObservedError> {
    if let Some(existing) = scenario
        .content
        .iter()
        .find(|body| body.reference.hash == reference.hash)
    {
        if &existing.reference != reference || existing.bytes != bytes {
            return Err(refused("ordinary accepted source body identity collision"));
        }
        return Ok(());
    }
    let total = scenario
        .content
        .iter()
        .try_fold(bytes.len(), |total, body| {
            total.checked_add(body.bytes.len())
        })
        .ok_or_else(|| refused("ordinary accepted body sum overflow"))?;
    if total > MAX_NODE_SCENARIO_BYTES {
        return Err(refused(
            "ordinary accepted body closure exceeds scenario limit",
        ));
    }
    reference.verify(bytes)?;
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(bytes.len())
        .map_err(|_| refused("ordinary accepted body allocation"))?;
    retained.extend_from_slice(bytes);
    scenario
        .content
        .try_reserve_exact(1)
        .map_err(|_| refused("ordinary accepted body roster allocation"))?;
    scenario.content.push(ScenarioContent {
        reference: reference.clone(),
        bytes: retained,
    });
    Ok(())
}

fn authenticate_original_report_binding(
    source: &BindingCompatibility,
    selected: &BindingCompatibility,
    report: &ContentRef,
) -> Result<(), NodeObservedError> {
    if selected != &with_original_report(source, report)? {
        return Err(refused("original ordinary report changed source semantics"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::U64;

    #[test]
    fn actual_clock_descriptor_transform_is_separate_from_report_only_binding_addition()
    -> Result<(), Box<dyn std::error::Error>> {
        let host =
            canonical::content_ref(b"measured host fixture data", "application/octet-stream")?;
        let device =
            canonical::content_ref(b"measured device fixture data", "application/octet-stream")?;
        let clock = InstalledNodeSelection {
            node: Id::new("clock")?,
            owner: Id::new("owner/clock")?,
            kind: InstalledNodeKind::HostClock,
        };
        let checksum = InstalledNodeSelection {
            node: Id::new("checksum")?,
            owner: Id::new("owner/checksum")?,
            kind: InstalledNodeKind::ReferenceDevice {
                quantum_ps: U64::new(1000),
                host_budget_ns: U64::new(1_000_000),
            },
        };
        let artifacts = BTreeMap::new();
        let raw = profile::build_world(std::slice::from_ref(&clock), &host, &device, &artifacts)?
            .scenario;
        let mixed = profile::build_world(&[checksum, clock], &host, &device, &artifacts)?.scenario;
        let public = super::super::super::normal_clock::profile::build(&raw)?;
        let report = canonical::content_ref(b"inert original report DATA", "application/json")?;
        let selected = with_original_report(&public.compatibility[0], &report)?;
        assert_ne!(raw.descriptors[0], public.descriptors[0]);
        assert_ne!(raw.compatibility[0], public.compatibility[0]);
        authenticate_original_report_binding(&public.compatibility[0], &selected, &report)?;
        assert!(
            authenticate_original_report_binding(&raw.compatibility[0], &selected, &report)
                .is_err()
        );
        let checksum = mixed
            .compatibility
            .iter()
            .find(|binding| binding.node_id.as_str() == "checksum")
            .ok_or("checksum binding")?;
        let mut foreign = selected.clone();
        foreign.execution_owner.id = checksum.execution_owner.id.clone();
        assert!(
            authenticate_original_report_binding(&public.compatibility[0], &foreign, &report)
                .is_err()
        );
        // This control uses only compiled profile DATA, never an Accepted
        // record, live class policy, graph, native node or source authority.
        Ok(())
    }
}

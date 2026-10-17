//! Uses model-only sealed graph data to test mandatory demand authentication.

// crucible-lint: allow panic-shortcut -- These model fixtures deliberately panic on unexpected contract invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::node_admission::{
    AdmissionEvidence, AdmissionLimits, AdmissionRequest, EvidenceError, QualificationClaim,
    evidence::VerifiedContent,
};
use crucible_node_contract::{
    ContentRef, ImplementationIdentity, NodeBinding, SchemaRef, canonical,
};
use std::collections::BTreeMap;

struct ModelContent(BTreeMap<String, Vec<u8>>);

impl AdmissionEvidence for ModelContent {
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError> {
        let bytes = self
            .0
            .get(&reference.hash.digest)
            .filter(|bytes| bytes.len() <= maximum_bytes)
            .ok_or_else(|| EvidenceError {
                message: "model content absent or oversized".into(),
            })?;
        Ok(bytes.clone())
    }
    fn authenticate_implementation(&self, _: &ImplementationIdentity) -> Result<(), EvidenceError> {
        Ok(())
    }
    fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
        Ok(())
    }
    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        Ok(())
    }
    fn qualify(&self, _: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        Ok(())
    }
    // Intentionally keeps the default capability-semantic refusal even though
    // all unrelated model qualification callbacks permit syntactically valid data.
}

fn put<T: serde::Serialize>(content: &mut ModelContent, value: &T, media_type: &str) -> ContentRef {
    let bytes = canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap();
    let reference = canonical::content_ref(&bytes, media_type).unwrap();
    content.0.insert(reference.hash.digest.clone(), bytes);
    reference
}

#[test]
fn permissive_other_qualification_cannot_grant_operation_support() {
    let (graph, blobs) = crate::node_admission::test_fixture_host_clock_execution();
    let mut content = ModelContent(blobs);
    let descriptors = graph.descriptors.values().cloned().collect::<Vec<_>>();
    let bindings = graph.bindings.values().cloned().collect::<Vec<_>>();
    let owners = graph.owners.values().cloned().collect::<Vec<_>>();
    let requirements = CapabilityRequirements {
        format: CAPABILITY_REQUIREMENTS_FORMAT.into(),
        schema_version: 1,
        nodes: bindings
            .iter()
            .map(|binding| {
                let actual = &binding.compatibility;
                let guarantees = graph.guarantees(&actual.node_id).unwrap();
                NodeCapabilityRequirement {
                    node: actual.node_id.clone(),
                    roles: vec![],
                    timing: TimingRequirement {
                        mode: actual.operating_contract.mode,
                        resolution_ps: actual.operating_contract.resolution_ps,
                        phase_ps: actual.operating_contract.phase_ps,
                        policy_ref: actual.operating_contract.policy_ref.clone(),
                    },
                    operations: vec![OperationRequirement {
                        operation: crucible_node_contract::Id::new("exact_run").unwrap(),
                        facet: actual.operating_contract.facets[0].clone(),
                    }],
                    guarantees: GuaranteeRequirement {
                        repeatability: guarantees.repeatability,
                        capture_scope: guarantees.capture_scope,
                        continuation: guarantees.continuation,
                        durable_restart: false,
                        isolated_fork: false,
                        conditional_replay: false,
                    },
                    compute: None,
                    extensions: vec![],
                }
            })
            .collect(),
    };
    let requirements_ref = put(
        &mut content,
        &requirements,
        CAPABILITY_REQUIREMENTS_MEDIA_TYPE,
    );
    let mut selection = CapabilitySelection {
        format: CAPABILITY_SELECTION_FORMAT.into(),
        schema_version: 1,
        base_scenario_ref: graph.world.scenario_ref.clone(),
        requirements_ref,
        bindings: bindings
            .iter()
            .map(|binding| CapabilityBinding {
                node: binding.compatibility.node_id.clone(),
                compatibility_hash: binding.compatibility.identity().unwrap(),
            })
            .collect(),
    };
    let mut world = graph.world.clone();
    world.scenario_ref = put(&mut content, &selection, CAPABILITY_SELECTION_MEDIA_TYPE);
    let request = AdmissionRequest {
        world: &world,
        descriptors: &descriptors,
        bindings: &bindings,
        owners: &owners,
        requirements: graph.requirements(),
    };
    let error = check_selection(
        &request,
        &graph.guarantees,
        graph.selected_extensions(),
        content
            .0
            .get(&world.scenario_ref.hash.digest)
            .unwrap()
            .clone(),
        &mut VerifiedContent::new(&content, AdmissionLimits::default()),
    )
    .unwrap_err();
    assert!(error.required.contains("installed operation"));
    assert_eq!(
        error.effects,
        crate::node_admission::EffectCertainty::Absent
    );

    // Even a correctly rehashed wrapper cannot replace one complete selected
    // compatibility hash with another member of the same otherwise valid world.
    selection.bindings[0].compatibility_hash = selection.bindings[1].compatibility_hash.clone();
    world.scenario_ref = put(&mut content, &selection, CAPABILITY_SELECTION_MEDIA_TYPE);
    let request = AdmissionRequest {
        world: &world,
        descriptors: &descriptors,
        bindings: &bindings,
        owners: &owners,
        requirements: graph.requirements(),
    };
    let error = check_selection(
        &request,
        &graph.guarantees,
        graph.selected_extensions(),
        content
            .0
            .get(&world.scenario_ref.hash.digest)
            .unwrap()
            .clone(),
        &mut VerifiedContent::new(&content, AdmissionLimits::default()),
    )
    .unwrap_err();
    assert!(error.required.contains("compatibility hashes"));
}

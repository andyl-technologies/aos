//! Tests real acceptance code with synthetic source profiles, without native qualification.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- These model fixtures fail immediately when a binding or acceptance invariant changes.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::{LiveAuthority, RealizationManifest, ResourceLimits};
use crucible_node_provider::{bodies::RealizeResult, reference_service::ReferenceProfile};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

struct CnpFixture {
    policy: Policy,
    profile: ReferenceProfile,
    result: RealizeResult,
    binding: NodeBinding,
    owner: crucible_node_contract::OwnerBinding,
    resources: ResourceLimits,
}

impl CnpFixture {
    fn new() -> Self {
        let mut policy = Policy::new();
        let reference = policy.fixture.claim.unit.environment.clone();
        let profile = ReferenceProfile::build_public_linked(
            id("node"),
            id("owner"),
            reference.clone(),
            reference.clone(),
            U64::new(1000),
            U64::new(1_000_000_000),
            true,
        )
        .unwrap();
        let authority = LiveAuthority {
            schema_version: 1,
            session_id: id("session"),
            incarnation_id: id("incarnation"),
            realization_id: id("realization"),
            activation_id: None,
            world_generation: U64::new(0),
            owner_generation: U64::new(1),
            input_epoch: id("input"),
            host_receipt: reference.clone(),
            extensions: Extensions::new(),
        };
        let (binding, owner) = profile
            .bind_qualified(authority, &[policy.fixture.reference.clone()])
            .unwrap();
        let result = RealizeResult {
            realization_manifest: RealizationManifest {
                schema_version: 1,
                realization_id: id("realization"),
                provider_manifest: reference.clone(),
                descriptors: vec![profile.descriptor.clone()],
                bindings: vec![binding.clone()],
                owners: vec![profile.owner.clone()],
                owner_bindings: vec![owner.clone()],
                extensions: Extensions::new(),
            },
            prepared_token: id("prepared"),
            closed_gate_receipt: reference,
        };
        let resources = ResourceLimits {
            cpu_budget_ns: U64::new(4_000_000_000),
            memory_bytes: U64::new(512 * 1024 * 1024),
            writable_bytes: U64::new(0),
            processes: U64::new(2),
            descriptors: U64::new(32),
            pending_events: U64::new(16),
            content_bytes: U64::new(16 * 1024 * 1024),
            maximum_operations: U64::new(8),
            extensions: Extensions::new(),
        };
        let projection = project_cnp_qualification(&profile, &result, &resources).unwrap();
        let values = [
            serde_json::to_value(&profile.implementation).unwrap(),
            serde_json::to_value((
                &profile.configuration_ref,
                &profile.node_manifest.profile_id,
                &result.realization_manifest.owners,
                &resources,
            ))
            .unwrap(),
            serde_json::to_value(&result.realization_manifest.descriptors).unwrap(),
            serde_json::to_value((
                &profile.operating_contract,
                &profile.capabilities,
                &profile.guarantees,
            ))
            .unwrap(),
            serde_json::to_value((&profile.node_manifest, &profile.descriptor.ports)).unwrap(),
        ];
        for value in values {
            let bytes = canonical::canonical_json(&value).unwrap();
            let reference = canonical::content_ref(&bytes, "application/json").unwrap();
            policy
                .fixture
                .authority
                .objects
                .insert(reference.hash.digest.clone(), (reference, bytes));
        }
        let unit = &mut policy.fixture.claim.unit;
        unit.implementation = projection.implementation;
        unit.realization = projection.realization;
        unit.descriptors = projection.descriptors;
        unit.contracts = projection.contracts;
        unit.port_profiles = projection.port_profiles;
        policy.required_classes = projection.required_classes;
        policy.fixture.claim.classes = policy.required_classes.clone();
        policy.fixture.claim.requirements[0].cases[0].classes = policy.required_classes.clone();
        policy.fixture.authority.policy.insert(
            policy.fixture.claim.requirements[0].requirement.clone(),
            Applicability::Applicable {
                classes: policy.required_classes.clone(),
            },
        );
        let mut fixture = Self {
            policy,
            profile,
            result,
            binding,
            owner,
            resources,
        };
        fixture.reencode();
        fixture
    }

    fn reencode(&mut self) {
        self.policy.fixture.encode_changed_original();
        let bytes = evaluate(&self.policy.fixture)
            .record()
            .canonical_bytes(8 * 1024 * 1024)
            .unwrap();
        self.policy.record = AcceptanceRecord::from_json(&bytes, bytes.len()).unwrap();
        self.binding.compatibility.qualification_refs = vec![self.policy.fixture.reference.clone()];
        self.policy.binding = self.binding.compatibility.clone();
        self.owner.node_bindings[0].binding_hash = self.binding.identity().unwrap();
        self.result.realization_manifest.bindings = vec![self.binding.clone()];
        self.result.realization_manifest.owner_bindings = vec![self.owner.clone()];
    }

    fn check(&self) -> Result<(), crucible::node_contract::OperationFailure> {
        CnpBehavioralAcceptance::new(&self.policy, AcceptanceLimits::default())
            .check(
                &self.profile,
                &self.result,
                &self.binding,
                &self.owner,
                &self.resources,
            )
            .map_err(|error| crucible::node_contract::OperationFailure {
                effects: crucible::node_contract::EffectKnowledge::Unknown,
                reason: error.to_string(),
            })
    }
}

#[test]
fn actual_projection_requires_all_source_classes_and_current_original_oracle() {
    let fixture = CnpFixture::new();
    assert!(fixture.check().is_ok());
    let before = fixture.policy.fixture.authority.case_calls.get();
    fixture.policy.reject_now.set(true);
    assert!(
        fixture.check().is_err(),
        "historical accepted data is not current evidence"
    );
    assert_eq!(fixture.policy.fixture.authority.case_calls.get(), before);

    let mut fixture = CnpFixture::new();
    fixture
        .policy
        .required_classes
        .remove(&QualificationClass::RoleProfile);
    assert!(
        fixture.check().is_err(),
        "vendor subset cannot omit actual semantic role"
    );
}

#[test]
fn source_binding_harness_original_and_model_only_success_cannot_be_substituted() {
    for change in 0..6 {
        let mut fixture = CnpFixture::new();
        match change {
            0 => fixture.policy.changed_unit = true,
            1 => {
                fixture.result.realization_manifest.bindings[0]
                    .compatibility
                    .profile_ref = fixture.policy.fixture.reference.clone()
            }
            2 => fixture.profile.operating_contract.resolution_ps = Some(U64::new(50)),
            3 => {
                fixture.policy.fixture.claim.requirements[0].cases[0].kind = CaseKind::Model;
                fixture.reencode();
                fixture.policy.record.decision = AcceptanceDecision::Accepted;
            }
            4 => fixture.binding.compatibility.qualification_refs.clear(),
            _ => fixture.resources.memory_bytes = U64::new(1024),
        }
        assert!(
            fixture.check().is_err(),
            "changed CNP scope {change} was accepted"
        );
    }
}

#[test]
fn source_projection_refuses_oversize_before_report_policy_or_byte_copy() {
    let mut fixture = CnpFixture::new();
    fixture.profile.descriptor.roles[0] = Id::new("large-role").unwrap();
    fixture.profile.descriptor.extensions.insert(
        "model.large".into(),
        serde_json::Value::String("x".repeat(256 * 1024)),
    );
    fixture.result.realization_manifest.descriptors = vec![fixture.profile.descriptor.clone()];
    let before = fixture.policy.fixture.authority.case_calls.get();
    assert!(
        project_cnp_qualification(&fixture.profile, &fixture.result, &fixture.resources).is_err()
    );
    assert_eq!(fixture.policy.fixture.authority.case_calls.get(), before);
}

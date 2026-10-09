//! Exercises registry data and refusal boundaries with explicit model-only authority.
//!
//! These tests do not qualify any native provider or promote execution/capture
//! support. A production-positive graph needs independently enrolled native
//! evidence for its exact extension-bearing world and selected profile.

// crucible-lint: allow panic-shortcut -- These extensions tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "frozen_admission_tests.rs"]
mod frozen_admission_tests;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use crucible_node_contract::*;

use super::*;
use crate::node_admission::{AdmissionCode, AdmissionLimits, AdmissionRequest, EvidenceError};

struct ModelGraphEvidence {
    registry: InstalledExtensionRegistry,
    blobs: BTreeMap<String, Vec<u8>>,
}

impl crate::node_admission::AdmissionEvidence for ModelGraphEvidence {
    fn extension_registry(&self) -> Option<&InstalledExtensionRegistry> {
        Some(&self.registry)
    }

    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        let bytes = self
            .blobs
            .get(&reference.hash.digest)
            .ok_or_else(|| error("model graph object absent"))?;
        if bytes.len() > maximum {
            return Err(error("model graph read exceeds credit"));
        }
        Ok(bytes.clone())
    }

    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError> {
        if implementation.implementation_id != id("test.qualified") {
            return Err(error("unknown model implementation"));
        }
        Ok(())
    }

    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError> {
        if binding.authority.session_id != id("host.session") {
            return Err(error("unknown model session"));
        }
        Ok(())
    }

    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError> {
        if schema.version != 1 || !self.blobs.contains_key(&schema.definition.hash.digest) {
            return Err(error("unknown model schema"));
        }
        Ok(())
    }

    fn qualify(
        &self,
        _: crate::node_admission::QualificationClaim<'_>,
    ) -> Result<(), EvidenceError> {
        // Explicit model-only trust matches the existing unit fixture. It never
        // authenticates a native process, provider, or installed production node.
        Ok(())
    }
}

pub(super) fn model_graph_with_extension() -> crate::node_admission::AdmittedGraph {
    let (baseline, blobs) = crate::node_admission::test_fixture_with_content();
    let mut policy = ModelInstallation::default();
    let registration = policy.registration("model/whole-graph-metadata", true);
    let mut world = baseline.world().clone();
    world.extensions = selected_map(&registration.selection);
    let evidence = ModelGraphEvidence {
        registry: install(vec![registration], &policy).unwrap(),
        blobs,
    };
    let descriptors: Vec<_> = baseline
        .node_ids()
        .map(|node| baseline.descriptor(node).unwrap().clone())
        .collect();
    let bindings: Vec<_> = baseline
        .node_ids()
        .map(|node| baseline.binding(node).unwrap().clone())
        .collect();
    let owners: Vec<_> = baseline.owners().cloned().collect();

    crate::node_admission::admit_graph(
        AdmissionRequest {
            world: &world,
            descriptors: &descriptors,
            bindings: &bindings,
            owners: &owners,
            requirements: baseline.requirements(),
        },
        &evidence,
        AdmissionLimits::default(),
    )
    .unwrap()
}

#[test]
fn whole_model_graph_admission_retains_exact_selected_extension_closure() {
    let graph = model_graph_with_extension();
    let selected = graph.selected_extensions();

    assert_eq!(selected.applications().len(), 1);
    assert_eq!(
        selected.applications().next().unwrap().scope().world_hash(),
        graph.world_binding_hash()
    );
    assert!(selected.objects().len() >= 3);
    for (reference, bytes) in selected.objects() {
        reference.verify(bytes).unwrap();
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn error(message: &str) -> EvidenceError {
    EvidenceError {
        message: message.into(),
    }
}

#[derive(Default)]
struct ModelInstallation {
    blobs: BTreeMap<ContentRef, Vec<u8>>,
    reads: Cell<usize>,
    callbacks: Rc<Cell<usize>>,
    deny_namespace: bool,
    deny_handler: bool,
    deny_schema: bool,
}

impl ModelInstallation {
    fn put(&mut self, bytes: &[u8]) -> ContentRef {
        let reference = canonical::content_ref(bytes, "application/json").unwrap();
        self.blobs.insert(reference.clone(), bytes.to_vec());
        reference
    }

    fn registration(&mut self, name: &str, qualify: bool) -> ExtensionRegistration {
        let semantic = self.put(b"model-only complete semantic contract; no native qualification");
        let schema = self.put(br#"{"type":"object","additionalProperties":false}"#);
        let declaration = ExtensionDeclaration {
            schema_version: 1,
            identifier: id(name),
            owner: ExtensionNamespaceOwner {
                authority: id("model/namespace-authority"),
                publication_origin: semantic.clone(),
            },
            semantic_version: SemanticVersion {
                major: U64::new(1),
                minor: U64::new(0),
                patch: U64::new(0),
                prerelease: None,
                build: None,
            },
            schema: SchemaRef {
                id: id("model/schema"),
                version: 1,
                definition: schema.clone(),
                extensions: BTreeMap::new(),
            },
            schema_digest: schema.hash,
            specification: semantic.clone(),
            dependencies: vec![],
            required_features: vec![],
            applicability: vec![ExtensionApplicability {
                location: ExtensionLocation::WorldBinding,
                operation_kinds: vec![],
                direction: None,
                roles: vec![],
                modes: vec![],
                facets: vec![],
                ports: vec![],
                lanes: vec![],
            }],
            timing_effects: semantic.clone(),
            state_effects: semantic.clone(),
            error_behavior: semantic.clone(),
            limits: ExtensionLimits {
                maximum_message_bytes: U64::new(4096),
                maximum_objects: U64::new(1),
                maximum_allocation_bytes: U64::new(4096),
                maximum_pending_events: U64::new(0),
                maximum_operations: U64::new(0),
            },
            conformance: semantic.clone(),
        };
        let selection = self.selection(&declaration);
        let semantics = ExtensionSemanticContract {
            class_contract: semantic.clone(),
            facet_contract: semantic.clone(),
            mode_contract: semantic.clone(),
            port_contract: semantic.clone(),
            timing_contract: semantic.clone(),
            state_contract: semantic.clone(),
            error_contract: semantic.clone(),
            qualification_contract: semantic.clone(),
            locations: BTreeSet::from([ExtensionRecordKind::WorldBinding]),
            roles: BTreeSet::new(),
            facets: BTreeSet::new(),
            modes: vec![],
            interfaces: BTreeSet::new(),
            impact: ExtensionImpact::Metadata,
        };
        ExtensionRegistration {
            selection,
            handler: Rc::new(ModelHandler {
                identity: semantic,
                semantics,
                identity_after_validation: None,
                changed: Cell::new(false),
                callbacks: Rc::clone(&self.callbacks),
            }),
            qualification: Rc::new(ModelQualification {
                allowed: qualify,
                callbacks: Rc::clone(&self.callbacks),
            }),
        }
    }

    fn selection(&mut self, declaration: &ExtensionDeclaration) -> ExtensionSelection {
        ExtensionSelection {
            declaration: self.put(&serde_json::to_vec(declaration).unwrap()),
            identifier: declaration.identifier.clone(),
            semantic_version: declaration.semantic_version.clone(),
            schema_digest: declaration.schema_digest.clone(),
        }
    }

    fn declaration(&self, selection: &ExtensionSelection) -> ExtensionDeclaration {
        canonical::decode(self.blobs.get(&selection.declaration).unwrap(), 4096).unwrap()
    }
}

impl ExtensionInstallationAuthority for ModelInstallation {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, EvidenceError> {
        self.reads.set(self.reads.get() + 1);
        let bytes = self
            .blobs
            .get(reference)
            .ok_or_else(|| error("model object absent"))?;
        if bytes.len() > maximum {
            return Err(error("model read exceeded pre-effect credit"));
        }
        Ok(bytes.clone())
    }

    fn authenticate_namespace(
        &self,
        declaration: &ExtensionDeclaration,
        _: &ExtensionSelection,
    ) -> Result<(), EvidenceError> {
        if self.deny_namespace || declaration.owner.authority != id("model/namespace-authority") {
            return Err(error("model namespace not authorized"));
        }
        Ok(())
    }

    fn authenticate_core_contract(
        &self,
        _: &Id,
        _: u16,
        _: &ContentRef,
    ) -> Result<(), EvidenceError> {
        Err(error("model policy has no installed core prerequisite"))
    }

    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        if self.deny_schema {
            return Err(error("model schema unavailable"));
        }
        Ok(())
    }

    fn authenticate_handler(
        &self,
        _: &ExtensionDeclaration,
        _: &ContentRef,
        _: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        if self.deny_handler {
            return Err(error("model handler unavailable"));
        }
        Ok(())
    }
}

struct ModelHandler {
    identity: ContentRef,
    semantics: ExtensionSemanticContract,
    identity_after_validation: Option<ContentRef>,
    changed: Cell<bool>,
    callbacks: Rc<Cell<usize>>,
}

impl ExtensionSemanticHandler for ModelHandler {
    fn identity(&self) -> &ContentRef {
        if self.changed.get()
            && let Some(identity) = &self.identity_after_validation
        {
            return identity;
        }
        &self.identity
    }
    fn semantics(&self) -> &ExtensionSemanticContract {
        &self.semantics
    }
    fn validate_application(
        &self,
        _: &ExtensionApplication<'_>,
        _: &ExtensionDeclaration,
        selected: &ExtensionUse,
    ) -> Result<(), EvidenceError> {
        self.callbacks.set(self.callbacks.get() + 1);
        if self.changed.get() || selected.parameters != serde_json::json!({}) {
            return Err(error("model closed object schema refused parameters"));
        }
        self.changed.set(self.identity_after_validation.is_some());
        Ok(())
    }
}

struct ModelQualification {
    allowed: bool,
    callbacks: Rc<Cell<usize>>,
}

impl ExtensionQualificationAuthority for ModelQualification {
    fn actual_features(
        &self,
        _: &ExtensionApplication<'_>,
        _: usize,
    ) -> Result<IdSet, EvidenceError> {
        self.callbacks.set(self.callbacks.get() + 1);
        Ok(vec![])
    }

    fn qualify_dependency(
        &self,
        _: &ExtensionApplication<'_>,
        _: &ExtensionUse,
        _: &ExtensionDeclaration,
        _: &ExtensionDeclaration,
        _: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        self.callbacks.set(self.callbacks.get() + 1);
        if !self.allowed {
            return Err(error(
                "model prerequisite lacks accepted dependency qualification",
            ));
        }
        Ok(())
    }
    fn qualify_application(
        &self,
        _: &ExtensionApplication<'_>,
        _: &ExtensionDeclaration,
        _: &ExtensionUse,
        _: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        self.callbacks.set(self.callbacks.get() + 1);
        if !self.allowed {
            return Err(error("model application lacks accepted qualification"));
        }
        Ok(())
    }
}

#[test]
fn declared_prerequisite_cannot_be_granted_by_a_permissive_qualifier() {
    let mut policy = ModelInstallation::default();
    let mut registration = policy.registration("model/requires-native-feature", true);
    let mut declaration = policy.declaration(&registration.selection);
    declaration.required_features = vec![id("cnp/not-negotiated")];
    registration.selection = policy.selection(&declaration);
    let selected = registration.selection.clone();
    let registry = install(vec![registration], &policy).unwrap();
    let mut seal = AdmittedExtensionSet::default();

    assert_eq!(
        apply(&registry, selected_map(&selected), &mut seal)
            .unwrap_err()
            .code,
        AdmissionCode::FeatureMismatch
    );
    assert!(seal.is_empty());
}

fn install(
    registrations: Vec<ExtensionRegistration>,
    policy: &ModelInstallation,
) -> Result<InstalledExtensionRegistry, crate::node_admission::AdmissionError> {
    InstalledExtensionRegistry::install(registrations, policy, ExtensionRegistryLimits::default())
}

fn selected_map(selection: &ExtensionSelection) -> Extensions {
    BTreeMap::from([(
        selection.identifier.as_str().to_owned(),
        serde_json::to_value(ExtensionUse {
            selection: selection.clone(),
            parameters: serde_json::json!({}),
        })
        .unwrap(),
    )])
}

fn apply(
    registry: &InstalledExtensionRegistry,
    extensions: Extensions,
    admitted: &mut AdmittedExtensionSet,
) -> Result<(), crate::node_admission::AdmissionError> {
    let (graph, _) = crate::node_admission::test_fixture_with_content();
    let mut world = graph.world().clone();
    world.extensions = extensions;
    let descriptors: Vec<_> = graph
        .node_ids()
        .map(|node| graph.descriptor(node).unwrap().clone())
        .collect();
    let bindings: Vec<_> = graph
        .node_ids()
        .map(|node| graph.binding(node).unwrap().clone())
        .collect();
    let owners: Vec<_> = graph.owners().cloned().collect();
    let request = AdmissionRequest {
        world: &world,
        descriptors: &descriptors,
        bindings: &bindings,
        owners: &owners,
        requirements: graph.requirements(),
    };
    let application = context::ExtensionApplication::for_record(
        &request,
        &world.identity().unwrap(),
        &world,
        &world.extensions,
        context::RecordPlacement {
            kind: ExtensionRecordKind::WorldBinding,
            node: None,
            path: ExtensionRecordPath::World,
        },
        AdmissionLimits::default(),
    )
    .unwrap();
    registry.admit_map(&application, &world.extensions, admitted)
}

#[test]
fn unknown_selection_preserves_empty_registry_refusal() {
    let mut policy = ModelInstallation::default();
    let selected = policy.registration("model/unknown", true).selection;
    let registry = install(vec![], &policy).unwrap();
    let mut seal = AdmittedExtensionSet::default();

    assert_eq!(
        apply(&registry, selected_map(&selected), &mut seal)
            .unwrap_err()
            .code,
        AdmissionCode::UnknownInterface
    );
    assert!(seal.is_empty());
    assert_eq!(policy.reads.get(), 0);
}

#[test]
fn matching_reference_does_not_bypass_namespace_handler_or_schema_policy() {
    for refusal in 0..3 {
        let mut policy = ModelInstallation::default();
        let registration = policy.registration("model/qualified", true);
        match refusal {
            0 => policy.deny_namespace = true,
            1 => policy.deny_handler = true,
            _ => policy.deny_schema = true,
        }

        assert_eq!(
            install(vec![registration], &policy).err().unwrap().code,
            AdmissionCode::QualificationUnavailable
        );
    }
}

#[test]
fn oversized_definition_is_refused_before_reader_allocation() {
    let mut policy = ModelInstallation::default();
    let registration = policy.registration("model/bounded", true);
    let limits = ExtensionRegistryLimits {
        maximum_object_bytes: 1,
        ..ExtensionRegistryLimits::default()
    };

    assert_eq!(
        InstalledExtensionRegistry::install(vec![registration], &policy, limits)
            .err()
            .unwrap()
            .code,
        AdmissionCode::BoundMismatch
    );
    assert_eq!(policy.reads.get(), 0);
}

#[test]
fn changed_content_refuses_even_when_configured_namespace_matches() {
    let mut policy = ModelInstallation::default();
    let registration = policy.registration("model/immutable", true);
    policy
        .blobs
        .get_mut(&registration.selection.declaration)
        .unwrap()[0] = b'[';

    assert_eq!(
        install(vec![registration], &policy).err().unwrap().code,
        AdmissionCode::InvalidSchema
    );
}

#[test]
fn published_version_cannot_be_redefined_at_another_content_hash() {
    let mut policy = ModelInstallation::default();
    let first = policy.registration("model/immutable-version", true);
    let mut second = policy.registration("model/immutable-version", true);
    let mut declaration = policy.declaration(&second.selection);
    declaration.specification = policy.put(b"different complete specification");
    second.selection = policy.selection(&declaration);

    assert_eq!(
        install(vec![first, second], &policy).err().unwrap().code,
        AdmissionCode::IdentityMismatch
    );
}

#[test]
fn missing_exact_dependency_refuses_complete_inventory() {
    let mut policy = ModelInstallation::default();
    let dependency = policy.registration("model/prerequisite", true).selection;
    let mut registration = policy.registration("model/dependent", true);
    let mut declaration = policy.declaration(&registration.selection);
    declaration
        .dependencies
        .push(ExtensionDependency::Extension {
            selection: dependency,
        });
    registration.selection = policy.selection(&declaration);

    assert_eq!(
        install(vec![registration], &policy).err().unwrap().code,
        AdmissionCode::UnknownInterface
    );
}

#[test]
fn valid_model_definition_still_requires_actual_application_qualification() {
    let mut policy = ModelInstallation::default();
    let registration = policy.registration("model/requires-qualification", false);
    let selected = registration.selection.clone();
    let registry = install(vec![registration], &policy).unwrap();
    let mut seal = AdmittedExtensionSet::default();

    assert_eq!(
        apply(&registry, selected_map(&selected), &mut seal)
            .unwrap_err()
            .code,
        AdmissionCode::QualificationUnavailable
    );
    assert!(seal.is_empty());
    assert_eq!(seal.objects().len(), 0);
}

#[test]
fn unknown_schema_fields_and_semantics_refuse_without_partial_seal() {
    let mut policy = ModelInstallation::default();
    let registration = policy.registration("model/schema", true);
    let selected = registration.selection.clone();
    let registry = install(vec![registration], &policy).unwrap();
    for malformed in [
        serde_json::json!({"unknown": 1}),
        serde_json::json!({"enabled": true}),
    ] {
        let mut map = selected_map(&selected);
        if let Some(value) = map.get_mut(selected.identifier.as_str()) {
            value["parameters"] = malformed;
        }
        let mut seal = AdmittedExtensionSet::default();

        assert_eq!(
            apply(&registry, map, &mut seal).unwrap_err().code,
            AdmissionCode::QualificationUnavailable
        );
        assert!(seal.is_empty());
    }
}

#[test]
fn exact_selected_dependency_objects_survive_without_unselected_registry_pollution() {
    let mut policy = ModelInstallation::default();
    let selected = policy.registration("model/selected", true);
    let selected_ref = selected.selection.clone();
    let unrelated = policy.registration("model/unselected", true);
    let unrelated_ref = unrelated.selection.declaration.clone();
    let registry = install(vec![selected, unrelated], &policy).unwrap();
    let mut seal = AdmittedExtensionSet::default();

    apply(&registry, selected_map(&selected_ref), &mut seal).unwrap();

    assert_eq!(seal.applications().len(), 1);
    assert!(
        seal.objects()
            .any(|(reference, _)| reference == &selected_ref.declaration)
    );
    assert!(
        !seal
            .objects()
            .any(|(reference, _)| reference == &unrelated_ref)
    );
    for (reference, bytes) in seal.objects() {
        reference.verify(bytes).unwrap();
    }
}

#[test]
fn dependency_cannot_relabel_an_installed_definition_to_another_version() {
    let mut policy = ModelInstallation::default();
    let child = policy.registration("model/prerequisite", true);
    let mut wrong = child.selection.clone();
    wrong.semantic_version.patch = U64::new(1);
    let mut parent = policy.registration("model/dependent", true);
    let mut declaration = policy.declaration(&parent.selection);
    declaration.dependencies = vec![ExtensionDependency::Extension { selection: wrong }];
    parent.selection = policy.selection(&declaration);

    assert_eq!(
        install(vec![parent, child], &policy).err().unwrap().code,
        AdmissionCode::IdentityMismatch
    );
}

#[test]
fn changed_map_key_and_unknown_selection_fields_are_refused() {
    let mut policy = ModelInstallation::default();
    let registration = policy.registration("model/exact-map", true);
    let selection = registration.selection.clone();
    let registry = install(vec![registration], &policy).unwrap();
    let mut different_key = selected_map(&selection);
    let body = different_key.remove(selection.identifier.as_str()).unwrap();
    different_key.insert("model/another-contract".into(), body);
    let mut seal = AdmittedExtensionSet::default();

    assert_eq!(
        apply(&registry, different_key, &mut seal).unwrap_err().code,
        AdmissionCode::IdentityMismatch
    );
    assert!(seal.is_empty());

    let mut unknown_field = selected_map(&selection);
    unknown_field
        .get_mut(selection.identifier.as_str())
        .unwrap()["selection"]["compatible"] = serde_json::json!(true);
    assert_eq!(
        apply(&registry, unknown_field, &mut seal).unwrap_err().code,
        AdmissionCode::InvalidSchema
    );
    assert!(seal.is_empty());
}

#[test]
fn a_later_failed_application_never_exposes_partial_selected_custody() {
    let mut policy = ModelInstallation::default();
    let first = policy.registration("model/a-accepted", true);
    let second = policy.registration("model/z-refused", false);
    let mut map = selected_map(&first.selection);
    map.extend(selected_map(&second.selection));
    let registry = install(vec![first, second], &policy).unwrap();
    let mut seal = AdmittedExtensionSet::default();

    assert_eq!(
        apply(&registry, map, &mut seal).unwrap_err().code,
        AdmissionCode::QualificationUnavailable
    );
    assert!(seal.is_empty());
    assert_eq!(seal.objects().len(), 0);
}

#[test]
fn deep_or_wide_parameter_values_refuse_before_clone_or_handler() {
    let mut nested = serde_json::Value::Null;
    for _ in 0..64 {
        nested = serde_json::json!([nested]);
    }
    let too_deep = BTreeMap::from([("model/deep".into(), nested)]);
    assert_eq!(
        selected::check_shapes(&too_deep).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );

    let too_wide = BTreeMap::from([(
        "model/wide".into(),
        serde_json::Value::Array(vec![serde_json::Value::Null; 65_536]),
    )]);
    assert_eq!(
        selected::check_shapes(&too_wide).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );
}

#[test]
fn node_only_class_requirement_cannot_be_satisfied_by_a_world_record() {
    let mut policy = ModelInstallation::default();
    let mut registration = policy.registration("model/context", true);
    let mut declaration = policy.declaration(&registration.selection);
    declaration.applicability[0].roles = vec![id("cpu")];
    registration.selection = policy.selection(&declaration);
    let map = selected_map(&registration.selection);
    let registry = install(vec![registration], &policy).unwrap();
    let mut seal = AdmittedExtensionSet::default();

    assert_eq!(
        apply(&registry, map, &mut seal).unwrap_err().code,
        AdmissionCode::FeatureMismatch
    );
    assert!(seal.is_empty());
}

#[test]
fn parameter_body_has_separate_pre_effect_selected_credit() {
    let mut policy = ModelInstallation::default();
    let mut registration = policy.registration("model/bounded-application", true);
    let mut declaration = policy.declaration(&registration.selection);
    declaration.limits.maximum_message_bytes = U64::new(512);
    declaration.limits.maximum_allocation_bytes = U64::new(512);
    registration.selection = policy.selection(&declaration);
    let map = selected_map(&registration.selection);
    let registry = InstalledExtensionRegistry::install(
        vec![registration],
        &policy,
        ExtensionRegistryLimits {
            maximum_total_application_bytes: 512,
            ..ExtensionRegistryLimits::default()
        },
    )
    .unwrap();
    let mut seal = AdmittedExtensionSet::default();

    assert_eq!(
        apply(&registry, map, &mut seal).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );
    assert!(seal.is_empty());
}

#[test]
fn interpretation_cannot_change_identity_after_installation() {
    let mut policy = ModelInstallation::default();
    let mut registration = policy.registration("model/immutable-handler", true);
    registration.handler = Rc::new(ModelHandler {
        identity: registration.handler.identity().clone(),
        semantics: registration.handler.semantics().clone(),
        identity_after_validation: Some(policy.put(b"uninstalled alternate interpretation")),
        changed: Cell::new(false),
        callbacks: Rc::clone(&policy.callbacks),
    });
    let map = selected_map(&registration.selection);
    let registry = install(vec![registration], &policy).unwrap();
    let mut seal = AdmittedExtensionSet::default();

    assert_eq!(
        apply(&registry, map, &mut seal).unwrap_err().code,
        AdmissionCode::IdentityMismatch
    );
    assert!(seal.is_empty());
    assert_eq!(seal.objects().len(), 0);
}

#[test]
fn transitive_prerequisite_features_are_checked_under_the_original_application() {
    let mut policy = ModelInstallation::default();
    let mut child = policy.registration("model/transitive-child", true);
    let mut declaration = policy.declaration(&child.selection);
    declaration.required_features = vec![id("cnp/absent-prerequisite")];
    child.selection = policy.selection(&declaration);
    let mut parent = policy.registration("model/transitive-parent", true);
    let mut declaration = policy.declaration(&parent.selection);
    declaration.dependencies = vec![ExtensionDependency::Extension {
        selection: child.selection.clone(),
    }];
    parent.selection = policy.selection(&declaration);
    let map = selected_map(&parent.selection);
    let registry = install(vec![parent, child], &policy).unwrap();
    let mut seal = AdmittedExtensionSet::default();

    assert_eq!(
        apply(&registry, map, &mut seal).unwrap_err().code,
        AdmissionCode::FeatureMismatch
    );
    assert!(seal.is_empty());
    assert_eq!(seal.objects().len(), 0);
}

#[test]
fn independently_unqualified_prerequisite_cannot_inherit_root_qualification() {
    let mut policy = ModelInstallation::default();
    let child = policy.registration("model/unqualified-child", false);
    let mut parent = policy.registration("model/qualified-parent", true);
    let mut declaration = policy.declaration(&parent.selection);
    declaration.dependencies = vec![ExtensionDependency::Extension {
        selection: child.selection.clone(),
    }];
    parent.selection = policy.selection(&declaration);
    let map = selected_map(&parent.selection);
    let registry = install(vec![parent, child], &policy).unwrap();
    let mut seal = AdmittedExtensionSet::default();

    assert_eq!(
        apply(&registry, map, &mut seal).unwrap_err().code,
        AdmissionCode::QualificationUnavailable
    );
    assert!(seal.is_empty());
    assert_eq!(seal.objects().len(), 0);
}

#[test]
fn entire_dependency_callback_budget_is_reserved_before_any_qualification() {
    let mut policy = ModelInstallation::default();
    let child = policy.registration("model/budget-child", true);
    let mut parent = policy.registration("model/budget-parent", true);
    let mut declaration = policy.declaration(&parent.selection);
    declaration.dependencies = vec![ExtensionDependency::Extension {
        selection: child.selection.clone(),
    }];
    parent.selection = policy.selection(&declaration);
    let map = selected_map(&parent.selection);
    let registry = InstalledExtensionRegistry::install(
        vec![parent, child],
        &policy,
        ExtensionRegistryLimits {
            maximum_qualification_checks: 3,
            ..ExtensionRegistryLimits::default()
        },
    )
    .unwrap();
    let mut seal = AdmittedExtensionSet::default();

    assert_eq!(
        apply(&registry, map, &mut seal).unwrap_err().code,
        AdmissionCode::BoundMismatch
    );
    assert!(seal.is_empty());
    assert_eq!(seal.objects().len(), 0);
    assert_eq!(policy.callbacks.get(), 0);
}

#[test]
fn qualified_dependency_path_executes_only_reserved_original_context_callbacks() {
    let mut policy = ModelInstallation::default();
    let child = policy.registration("model/accepted-child", true);
    let mut parent = policy.registration("model/accepted-parent", true);
    let mut declaration = policy.declaration(&parent.selection);
    declaration.dependencies = vec![ExtensionDependency::Extension {
        selection: child.selection.clone(),
    }];
    parent.selection = policy.selection(&declaration);
    let map = selected_map(&parent.selection);
    let registry = InstalledExtensionRegistry::install(
        vec![parent, child],
        &policy,
        ExtensionRegistryLimits {
            maximum_qualification_checks: 5,
            ..ExtensionRegistryLimits::default()
        },
    )
    .unwrap();
    let mut seal = AdmittedExtensionSet::default();

    apply(&registry, map, &mut seal).unwrap();

    assert_eq!(policy.callbacks.get(), 3);
    assert_eq!(seal.applications().len(), 1);
}

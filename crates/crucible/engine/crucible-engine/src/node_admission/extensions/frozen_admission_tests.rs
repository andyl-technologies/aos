//! Refuses post-qualification semantic drift without issuing model admission.

// crucible-lint: allow panic-shortcut -- These frozen admission tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

struct SwitchingSemantics {
    identity: ContentRef,
    before: ExtensionSemanticContract,
    after: ExtensionSemanticContract,
    validated: Cell<bool>,
}

struct CrossApplicationHandler {
    identity: ContentRef,
    before: ExtensionSemanticContract,
    after: ExtensionSemanticContract,
    changed: Rc<Cell<bool>>,
    change_other: Option<Rc<Cell<bool>>>,
}

impl ExtensionSemanticHandler for CrossApplicationHandler {
    fn identity(&self) -> &ContentRef {
        &self.identity
    }

    fn semantics(&self) -> &ExtensionSemanticContract {
        if self.changed.get() {
            &self.after
        } else {
            &self.before
        }
    }

    fn validate_application(
        &self,
        _: &ExtensionApplication<'_>,
        _: &ExtensionDeclaration,
        _: &ExtensionUse,
    ) -> Result<(), EvidenceError> {
        if let Some(other) = &self.change_other {
            other.set(true);
        }
        Ok(())
    }
}

impl ExtensionSemanticHandler for SwitchingSemantics {
    fn identity(&self) -> &ContentRef {
        &self.identity
    }

    fn semantics(&self) -> &ExtensionSemanticContract {
        if self.validated.get() {
            &self.after
        } else {
            &self.before
        }
    }

    fn validate_application(
        &self,
        _: &ExtensionApplication<'_>,
        _: &ExtensionDeclaration,
        _: &ExtensionUse,
    ) -> Result<(), EvidenceError> {
        self.validated.set(true);
        Ok(())
    }
}

#[test]
fn changed_actual_typed_semantics_cannot_be_recalibrated_under_original_code_identity() {
    for axis in 0..14 {
        let mut policy = ModelInstallation::default();
        let mut registration = policy.registration("model/semantic-drift", true);
        let before = registration.handler.semantics().clone();
        let mut after = before.clone();
        let changed = policy.put(b"other semantic body; cannot replace admitted calibration");
        match axis {
            0 => after.class_contract = changed,
            1 => after.facet_contract = changed,
            2 => after.mode_contract = changed,
            3 => after.port_contract = changed,
            4 => after.timing_contract = changed,
            5 => after.state_contract = changed,
            6 => after.error_contract = changed,
            7 => after.qualification_contract = changed,
            8 => after.locations = BTreeSet::from([ExtensionRecordKind::NodeDescriptor]),
            9 => after.roles = BTreeSet::from([id("clock")]),
            10 => after.facets = BTreeSet::from([id("model/execution")]),
            11 => after.modes = vec![OperatingMode::Exact],
            12 => after.interfaces = BTreeSet::from([id("model/interface")]),
            13 => after.impact = ExtensionImpact::Behavior,
            _ => unreachable!(),
        }
        registration.handler = Rc::new(SwitchingSemantics {
            identity: registration.handler.identity().clone(),
            before,
            after,
            validated: Cell::new(false),
        });
        let selection = registration.selection.clone();
        let registry = install(vec![registration], &policy).unwrap();
        let mut seal = AdmittedExtensionSet::default();

        let failure = apply(&registry, selected_map(&selection), &mut seal).unwrap_err();

        assert_eq!(failure.code, AdmissionCode::IdentityMismatch, "axis {axis}");
        assert!(seal.is_empty());
        assert_eq!(seal.objects().len(), 0);
    }
}

#[test]
fn empty_selection_preserves_original_identity_bytes_and_domain() {
    let seal = AdmittedExtensionSet::default();
    let original = serde_json::json!({"applications": [], "definitions": []});

    assert_eq!(
        seal.identity().unwrap(),
        canonical::json_hash("cnp.selected-extensions.v1", &original).unwrap()
    );
    assert_eq!(seal.definitions().len(), 0);
}

#[test]
fn direct_and_prerequisite_interpretations_are_frozen_under_identity_two() {
    let mut policy = ModelInstallation::default();
    let child = policy.registration("model/frozen-child", true);
    let mut parent = policy.registration("model/frozen-parent", true);
    let child_contract = child.handler.semantics().clone();
    let parent_contract = parent.handler.semantics().clone();
    let child_selection = child.selection.clone();
    let mut declaration = policy.declaration(&parent.selection);
    declaration.dependencies = vec![ExtensionDependency::Extension {
        selection: child_selection.clone(),
    }];
    parent.selection = policy.selection(&declaration);
    let map = selected_map(&parent.selection);
    let registry = install(vec![parent, child], &policy).unwrap();
    let mut seal = AdmittedExtensionSet::default();

    apply(&registry, map, &mut seal).unwrap();

    assert_eq!(
        seal.applications().next().unwrap().semantic_contract(),
        &parent_contract
    );
    let definitions: Vec<_> = seal.definitions().collect();
    assert_eq!(definitions.len(), 2);
    let prerequisite = definitions
        .iter()
        .find(|definition| definition.selection() == &child_selection)
        .unwrap();
    assert_eq!(prerequisite.semantic_contract(), &child_contract);
    let original = serde_json::json!({"schema_version": 2, "applications": seal.applications().collect::<Vec<_>>(), "definitions": definitions});
    assert_eq!(
        seal.identity().unwrap(),
        canonical::json_hash("cnp.selected-extensions.v2", &original).unwrap()
    );
    assert_ne!(
        seal.identity().unwrap().domain,
        "cnp.selected-extensions.v1"
    );
}

#[test]
fn complete_semantic_snapshot_credit_is_reserved_before_native_qualification() {
    let mut policy = ModelInstallation::default();
    let registration = policy.registration("model/frozen-credit", true);
    let map = selected_map(&registration.selection);
    let registry = InstalledExtensionRegistry::install(
        vec![registration],
        &policy,
        ExtensionRegistryLimits {
            // The declaration legitimately permits a 4 KiB message. The full
            // scope plus application and independent definition exceed that
            // aggregate without invalidating installation allowances.
            maximum_total_application_bytes: 4096,
            ..ExtensionRegistryLimits::default()
        },
    )
    .unwrap();
    let mut seal = AdmittedExtensionSet::default();

    let error = apply(&registry, map, &mut seal).unwrap_err();

    assert_eq!(error.code, AdmissionCode::BoundMismatch);
    assert_eq!(policy.callbacks.get(), 0);
    assert!(seal.is_empty());
    assert_eq!(seal.definitions().len(), 0);
    assert_eq!(seal.objects().len(), 0);
}

#[test]
fn later_handler_cannot_change_an_earlier_qualified_interpretation() {
    let mut policy = ModelInstallation::default();
    let mut first = policy.registration("model/a-original", true);
    let mut later = policy.registration("model/z-mutator", true);
    let first_changed = Rc::new(Cell::new(false));
    let first_contract = first.handler.semantics().clone();
    let mut changed_contract = first_contract.clone();
    changed_contract.class_contract = policy.put(b"changed after first qualification");
    let first_identity = first.handler.identity().clone();
    first.handler = Rc::new(CrossApplicationHandler {
        identity: first_identity.clone(),
        before: first_contract,
        after: changed_contract,
        changed: Rc::clone(&first_changed),
        change_other: None,
    });
    let later_contract = later.handler.semantics().clone();
    later.handler = Rc::new(CrossApplicationHandler {
        identity: later.handler.identity().clone(),
        before: later_contract.clone(),
        after: later_contract,
        changed: Rc::new(Cell::new(false)),
        change_other: Some(Rc::clone(&first_changed)),
    });
    let first_handler = Rc::clone(&first.handler);
    let mut map = selected_map(&first.selection);
    map.extend(selected_map(&later.selection));
    let registry = install(vec![first, later], &policy).unwrap();
    let mut seal = AdmittedExtensionSet::default();

    let error = apply(&registry, map, &mut seal).unwrap_err();

    assert!(first_changed.get());
    assert_eq!(first_handler.identity(), &first_identity);
    assert_eq!(error.code, AdmissionCode::IdentityMismatch);
    assert!(seal.is_empty());
    assert_eq!(seal.definitions().len(), 0);
    assert_eq!(seal.objects().len(), 0);
}

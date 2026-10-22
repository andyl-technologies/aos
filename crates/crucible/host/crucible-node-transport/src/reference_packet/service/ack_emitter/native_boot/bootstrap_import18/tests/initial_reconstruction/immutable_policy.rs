//! Exercises original model-absent policy ownership under actual SDK/Hello custody.
//!
//! The fixture rebuilds full immutable identities before receipt. Its admission
//! callbacks remain model controls and supply no genuine Source/Birth grant.

use super::super::super::immutable_policy::OriginalImport18ImmutablePolicyAdmission;
use super::*;
use crate::reference_packet::NativeImport18PolicyData;
use crate::reference_packet::service::complete_restore::import18::{
    native_import18_declared_features_data, native_import18_restored_record_schema_data,
    native_import18_schema_data, native_import18_stage_schema_data,
};
use crucible_node_format::Validate;
use std::{cell::Cell, rc::Rc};

/// Builds a valid complete launch with full18 declarations before hashing its World.
pub(super) fn prepare_selected(case: &str, selected: &mut Value) {
    let bytes: Bytes =
        serde_json::from_value(selected["launch"]["initial_coordinator"]["bytes"].clone()).unwrap();
    let mut coordinator: crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation = serde_json::from_slice(bytes.as_slice()).unwrap();
    let member = usize::from(case == "initial_policy_reactive");
    let peer = &mut coordinator.participants[member];
    peer.provider.implementation.formats.extend([
        native_import18_schema_data().unwrap(),
        native_import18_stage_schema_data().unwrap(),
        native_import18_restored_record_schema_data().unwrap(),
    ]);
    peer.provider
        .implementation
        .formats
        .sort_by(|a, b| a.id.cmp(&b.id));
    peer.provider
        .extensions_supported
        .extend(native_import18_declared_features_data().map(|name| Id::new(name).unwrap()));
    peer.provider.extensions_supported.sort();
    peer.provider.validate().unwrap();
    peer.realization.bindings[0].compatibility.implementation =
        peer.provider.implementation.clone();
    peer.realization.provider_manifest = canonical::content_ref(
        &canonical::canonical_json(&json!(peer.provider)).unwrap(),
        "application/json",
    )
    .unwrap();
    let binding_hash = peer.realization.bindings[0].identity().unwrap();
    peer.realization.owner_bindings[0].node_bindings[0].binding_hash = binding_hash.clone();
    coordinator.template["nodes"][member]["binding"] = json!(peer.realization.bindings[0]);
    coordinator.template["owner_bindings"][member] = json!(peer.realization.owner_bindings[0]);

    let mut world: crucible_node_format::WorldBinding =
        serde_json::from_value(coordinator.template["world"].clone()).unwrap();
    world.node_bindings[member].binding_hash = binding_hash;
    let world_identity = world.identity().unwrap();
    coordinator.template["world"] = json!(world);
    coordinator.template["activation"]["world_binding_hash"] = json!(world_identity);
    for peer in &mut coordinator.participants {
        peer.world = world_identity.clone();
    }
    coordinator
        .validate(&coordinator.participants[member])
        .unwrap();
    let body = canonical::canonical_json(&json!(coordinator)).unwrap();
    selected["launch"]["initial_coordinator"] = json!({
        "reference": canonical::content_ref(&body, "application/json").unwrap(),
        "bytes": Bytes::new(body),
    });
    super::launch_validation::prepare_selected(
        if member == 1 {
            "initial_launch_validation_reactive"
        } else {
            "initial_launch_validation_complete"
        },
        selected,
    );
}

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18ImmutablePolicyAdmission for Admission<'_> {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert_eq!(original.immutable_policy.row_data(), Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        assert_eq!(original.immutable_policy_backing_data().unwrap(), 0);
        self.row.set(Some(row));
        if self.case == "initial_policy_construct_refused" {
            return Err(ProviderError::Conflict("policy construction refused"));
        }
        if self.case == "initial_policy_construct_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(2), 1);
        assert_eq!(
            actual,
            NativeImport18PolicyData::shared_backing_data().unwrap()
        );
        assert_eq!(actual, self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        if self.case == "initial_policy_finish_refused" {
            return Err(ProviderError::Conflict("policy terminal census refused"));
        }
        if self.case == "initial_policy_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn publishes(case: &str) -> bool {
    case != "initial_policy_without_publication"
}

pub(super) fn assert_child(case: &str, original: &mut OriginalImport18RawBootstrap) {
    if case != "initial_policy_without_validation" {
        super::launch_validation::validate_for_policy(original);
    }
    if publishes(case) {
        super::hello_publication::construct_for_policy(original);
    } else {
        super::hello_admission::construct_for_publication(original);
    }
    let before = original.retained_requested_bytes().unwrap();
    let pointers = original.bodies.each_ref().map(|body| body.as_ptr());
    let launch_pointer = Rc::as_ptr(original.parsed.shared_launch_data().unwrap());
    let launch_edges = Rc::strong_count(original.parsed.shared_launch_data().unwrap());
    let authority = original
        .hello_registrar
        .retained_authority_fixture_data()
        .map(std::ptr::from_ref);
    assert!(original.with_immutable_policy_data(|_| Ok(())).is_err());
    if case == "initial_policy_selection_revoked" {
        original.selection_authenticated = false;
    }
    if case == "initial_policy_before_expired" {
        std::thread::sleep(Duration::from_secs(5));
    }
    let admission = Admission {
        case,
        calls: Cell::new(0),
        before,
        row: Cell::new(None),
    };

    let outcome = original.construct_immutable_policy_data(&admission);

    let success = matches!(
        case,
        "initial_policy_complete"
            | "initial_policy_reactive"
            | "initial_policy_callback_refused"
            | "initial_policy_loan_expired"
            | "initial_policy_substituted_cut"
            | "initial_policy_later_contained"
    );
    if success {
        outcome.unwrap();
        assert_eq!(admission.calls.get(), 2);
        original
            .with_immutable_policy_data(|policy| {
                policy.authenticate_original_data(original.parsed.shared_launch_data()?)?;
                assert_eq!(
                    std::ptr::from_ref(policy.launch_data()),
                    std::ptr::from_ref(original.typed_bodies_data()?.launch.launch_data())
                );
                assert_eq!(
                    policy.recipe_identity_data(),
                    original
                        .typed_bodies_data()?
                        .recipe
                        .announced_identity_data()
                );
                assert_eq!(
                    policy.hello_data(),
                    original.with_published_hello_frame_digests_data(Ok)?
                );
                assert_eq!(
                    policy.definitions_data()?.map(|schema| schema.version),
                    [18; 3]
                );
                // Equal DTOs in a different shared allocation receive no alias discount.
                let equal: PacketNativeImport18SelectedLaunchWireData = serde_json::from_value(
                    serde_json::to_value(original.parsed.shared_launch_data()?.as_ref()).unwrap(),
                )
                .unwrap();
                assert!(policy.authenticate_original_data(&Rc::new(equal)).is_err());
                Ok(())
            })
            .unwrap();
        if case == "initial_policy_callback_refused" {
            assert!(
                original
                    .with_immutable_policy_data::<()>(|_| Err(ProviderError::Conflict(
                        "policy inspection refused"
                    )))
                    .is_err()
            );
            original.with_immutable_policy_data(|_| Ok(())).unwrap();
        }
        if case == "initial_policy_substituted_cut" {
            let prior = original.cut;
            original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
            assert!(original.with_immutable_policy_data(|_| Ok(())).is_err());
            original.cut = prior;
            original.with_immutable_policy_data(|_| Ok(())).unwrap();
        }
        if case == "initial_policy_loan_expired" {
            assert!(
                original
                    .with_immutable_policy_data(|_| {
                        std::thread::sleep(Duration::from_secs(5));
                        Ok(())
                    })
                    .is_err()
            );
            assert!(original.with_immutable_policy_data(|_| Ok(())).is_err());
        }
        if case == "initial_policy_later_contained" {
            original.hello_registrar.contain_admission_data().unwrap();
            assert!(original.with_immutable_policy_data(|_| Ok(())).is_err());
        }
    } else {
        assert!(outcome.is_err(), "{case}");
        assert!(original.with_immutable_policy_data(|_| Ok(())).is_err());
        assert!(
            original
                .with_hello_authority_data(|lease| lease.ensure_live())
                .is_err()
        );
    }
    let calls = admission.calls.get();
    assert!(
        original
            .construct_immutable_policy_data(&admission)
            .is_err()
    );
    assert_eq!(admission.calls.get(), calls);
    let backing = original.immutable_policy_backing_data().unwrap();
    assert_eq!(
        original.retained_requested_bytes().unwrap(),
        before + backing
    );
    assert_eq!(
        Rc::strong_count(original.parsed.shared_launch_data().unwrap()),
        launch_edges + usize::from(backing != 0)
    );
    assert_eq!(
        Rc::as_ptr(original.parsed.shared_launch_data().unwrap()),
        launch_pointer
    );
    assert_eq!(
        original.bodies.each_ref().map(|body| body.as_ptr()),
        pointers
    );
    assert_eq!(
        original
            .hello_registrar
            .retained_authority_fixture_data()
            .map(std::ptr::from_ref),
        authority
    );
    assert!(original.inputs.is_empty_data());
}

#[test]
fn model_absent_policy_keeps_actual_launch_hello_lease_and_every_terminal_owner() {
    for case in [
        "initial_policy_complete",
        "initial_policy_reactive",
        "initial_policy_without_validation",
        "initial_policy_without_publication",
        "initial_policy_selection_revoked",
        "initial_policy_before_expired",
        "initial_policy_construct_refused",
        "initial_policy_construct_expired",
        "initial_policy_finish_refused",
        "initial_policy_finish_expired",
        "initial_policy_callback_refused",
        "initial_policy_loan_expired",
        "initial_policy_substituted_cut",
        "initial_policy_later_contained",
    ] {
        flight(case);
    }
}

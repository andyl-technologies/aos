//! Exercises original model-absent policy ownership under actual SDK/Hello custody.
//!
//! The fixture rebuilds full immutable identities before receipt. Its admission
//! callbacks remain model controls and supply no genuine Source/Birth grant.

use super::super::super::immutable_policy::OriginalImport18ImmutablePolicyAdmission;
use super::*;
use crate::reference_packet::NativeImport18PolicyData;
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18BootstrapTypedBirthView;
use crate::reference_packet::service::complete_restore::import18::hello::PacketNativeImport18CurrentRegistrationView;
use crate::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18PrivateBootWireData, native_import18_declared_features_data,
    native_import18_restored_record_schema_data, native_import18_schema_data,
    native_import18_stage_schema_data,
};
use crucible_node_format::Validate;
use std::{cell::Cell, rc::Rc};

/// Builds a valid complete launch with full18 declarations before hashing its World.
pub(super) fn prepare_selected(case: &str, selected: &mut Value) {
    let bytes: Bytes =
        serde_json::from_value(selected["launch"]["initial_coordinator"]["bytes"].clone()).unwrap();
    let mut coordinator: crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation = serde_json::from_slice(bytes.as_slice()).unwrap();
    let member = usize::from(matches!(
        case,
        "initial_policy_reactive"
            | "initial_policy_kernel_reactive"
            | "initial_policy_kernel_operands_reactive"
            | "initial_policy_kernel_normalizations_reactive"
            | "initial_policy_kernel_normalizations_host_reactive"
    ));
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
    assert!(
        original
            .with_bootstrap_policy_wire_data(|_| Ok(()))
            .is_err()
    );
    assert!(original.with_bootstrap_birth_wire_data(|_| Ok(())).is_err());
    assert!(
        original
            .with_bootstrap_native_registration_wire_data(|_| Ok(()))
            .is_err()
    );
    if case == "initial_policy_kernel_missing_policy" {
        super::bootstrap_kernel::assert_missing_policy(original);
        return;
    }
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
            | "initial_policy_registration_loan_expired"
            | "initial_policy_registration_error_expired"
            | "initial_policy_substituted_cut"
            | "initial_policy_later_contained"
    ) || case.starts_with("initial_policy_kernel_");
    if success {
        outcome.unwrap();
        assert_eq!(admission.calls.get(), 2);
        // Individual policy/birth/registration flights own these independent
        // field oracles. Kernel and normalization flights exercise their own
        // original guarded operation within the same unchanged five-second cut.
        if !case.starts_with("initial_policy_kernel_") {
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
                        serde_json::to_value(original.parsed.shared_launch_data()?.as_ref())
                            .unwrap(),
                    )
                    .unwrap();
                    assert!(policy.authenticate_original_data(&Rc::new(equal)).is_err());
                    Ok(())
                })
                .unwrap();
            original
                .with_bootstrap_policy_wire_data(|view| {
                    assert_bootstrap_policy_wire(&original, view)
                })
                .unwrap();
            original
                .with_bootstrap_birth_wire_data(|view| assert_bootstrap_birth_wire(&original, view))
                .unwrap();
            original
                .with_bootstrap_native_registration_wire_data(|view| {
                    assert_bootstrap_native_registration(original, view)
                })
                .unwrap();
        }
        if case.starts_with("initial_policy_kernel_") {
            super::bootstrap_kernel::assert_child(case, original);
        }
        if case == "initial_policy_callback_refused" {
            assert!(
                original
                    .with_bootstrap_native_registration_wire_data::<()>(|_| Err(
                        ProviderError::Conflict("native registration callback model")
                    ))
                    .is_err()
            );
            assert!(
                original
                    .with_bootstrap_birth_wire_data::<()>(|_| Err(ProviderError::Conflict(
                        "policy inspection refused"
                    )))
                    .is_err()
            );
            original.with_immutable_policy_data(|_| Ok(())).unwrap();
        }
        if case == "initial_policy_substituted_cut" {
            let prior = original.cut;
            original.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
            assert!(
                original
                    .with_bootstrap_native_registration_wire_data(|_| Ok(()))
                    .is_err()
            );
            assert!(original.with_bootstrap_birth_wire_data(|_| Ok(())).is_err());
            original.cut = prior;
            original.with_immutable_policy_data(|_| Ok(())).unwrap();
        }
        if matches!(
            case,
            "initial_policy_registration_loan_expired"
                | "initial_policy_registration_error_expired"
        ) {
            assert!(
                original
                    .with_bootstrap_native_registration_wire_data(|_| {
                        std::thread::sleep(Duration::from_secs(5));
                        if case == "initial_policy_registration_error_expired" {
                            Err(ProviderError::Conflict(
                                "expired native registration callback model",
                            ))
                        } else {
                            Ok(())
                        }
                    })
                    .is_err()
            );
            assert!(
                original
                    .with_hello_authority_data(|lease| lease.ensure_live())
                    .is_err()
            );
        }
        if case == "initial_policy_loan_expired" {
            assert!(
                original
                    .with_bootstrap_birth_wire_data(|_| {
                        std::thread::sleep(Duration::from_secs(5));
                        Ok(())
                    })
                    .is_err()
            );
            assert!(original.with_immutable_policy_data(|_| Ok(())).is_err());
            assert!(
                original
                    .with_bootstrap_native_registration_wire_data(|_| Ok(()))
                    .is_err()
            );
        }
        if case == "initial_policy_later_contained" {
            original.hello_registrar.contain_admission_data().unwrap();
            assert!(
                original
                    .with_bootstrap_native_registration_wire_data(|_| Ok(()))
                    .is_err()
            );
            assert!(original.with_bootstrap_birth_wire_data(|_| Ok(())).is_err());
        }
    } else {
        assert!(outcome.is_err(), "{case}");
        assert!(
            original
                .with_bootstrap_policy_wire_data(|_| Ok(()))
                .is_err()
        );
        assert!(original.with_bootstrap_birth_wire_data(|_| Ok(())).is_err());
        assert!(
            original
                .with_bootstrap_native_registration_wire_data(|_| Ok(()))
                .is_err()
        );
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
        before + backing + original.bootstrap_kernel.retained_backing_data().unwrap()
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
        "initial_policy_kernel_complete",
        "initial_policy_kernel_reactive",
        "initial_policy_kernel_missing_policy",
        "initial_policy_kernel_construct_refused",
        "initial_policy_kernel_construct_expired",
        "initial_policy_kernel_finish_refused",
        "initial_policy_kernel_finish_expired",
        "initial_policy_kernel_callback_refused",
        "initial_policy_kernel_loan_expired",
        "initial_policy_kernel_operands_complete",
        "initial_policy_kernel_operands_reactive",
        "initial_policy_kernel_operands_loan_expired",
        "initial_policy_kernel_operands_error_expired",
        "initial_policy_kernel_operands_callback_refused",
        "initial_policy_kernel_operands_changed_loan_cut",
        "initial_policy_kernel_substituted_cut",
        "initial_policy_kernel_later_contained",
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
        "initial_policy_registration_loan_expired",
        "initial_policy_registration_error_expired",
        "initial_policy_substituted_cut",
        "initial_policy_later_contained",
    ] {
        flight(case);
    }
}

/// Checks the borrowed policy against its independent wire and allocation oracles.
fn assert_bootstrap_policy_wire(
    original: &OriginalImport18RawBootstrap,
    view: &crate::reference_packet::service::complete_restore::import18::bootstrap_ack::PacketNativeImport18BootstrapTypedPolicyView<'_>,
) -> Result<(), ProviderError> {
    use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::native_import18_bootstrap_policy_wire_data;
    use crate::retained_metadata::MetadataObserver;
    use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;

    let bodies = original.typed_bodies_data()?;
    let source_binding = bodies.boot.source_binding_data();
    let source_birth = source_binding.declaration_data().source_birth_data();
    assert!(std::ptr::eq(view.source_binding_data(), source_binding));
    let projected = view.serialization_data(usize::MAX).unwrap();
    let policy_value = serde_json::to_value(view).unwrap();
    let source_value = serde_json::to_value(source_binding).unwrap();
    let recipe = Bytes::new(bodies.recipe.announced_identity_data().to_vec());
    original.with_immutable_policy_data(|policy| {
        original.with_hello_authority_data(|lease| {
            let [import, stage, record] = policy.definitions_data()?;
            let expected = native_import18_bootstrap_policy_wire_data(
                &source_value,
                &recipe,
                import,
                stage,
                record,
                lease,
            )?;
            assert_eq!(policy_value, serde_json::to_value(expected).unwrap());
            Ok(())
        })
    })?;

    // These are the actual two Bytes leaves of the typed policy. Other
    // fields contain closed scalars, string-backed refs and Id rosters.
    let mut observer = MetadataObserver::new();
    observer.observe(source_birth).unwrap();
    observer.observe(&recipe).unwrap();
    let actual = actual_serialization_storage_data(view, observer.finish(), usize::MAX).unwrap();
    assert_eq!(
        projected.maximum_encoded_bytes,
        actual.maximum_encoded_bytes
    );
    assert_eq!(
        projected.serialized_value_nodes,
        actual.serialized_value_nodes
    );
    assert_eq!(
        projected.serialized_capacity_records,
        actual.serialized_capacity_records
    );
    assert_eq!(
        projected.retained_value_backing_bytes,
        actual.retained_value_backing_bytes
    );
    assert_eq!(
        projected.dom_and_canonical_scratch_bytes,
        actual.dom_and_canonical_scratch_bytes
    );
    assert_eq!(
        projected.projected_parser_requested_bytes,
        actual.projected_parser_requested_bytes
    );
    assert_eq!(
        projected.canonical_output_requested_bytes,
        actual.canonical_output_requested_bytes
    );
    assert_eq!(
        projected.serializer_temporary_requested_bytes,
        Bytes::borrowed_serialization_temporary_bytes_data(source_birth.as_slice())
            .unwrap()
            .max(43)
    );
    let peak = projected.requested_total().unwrap();
    assert_eq!(
        policy_shape_fields(&view.serialization_data(peak).unwrap()),
        policy_shape_fields(&projected)
    );
    assert!(view.serialization_data(peak - 1).is_err());
    assert_eq!(
        policy_shape_fields(&view.serialization_data(peak + 4096).unwrap()),
        policy_shape_fields(&projected)
    );
    assert!(view.serialization_data(1).is_err());
    assert!(
        OriginalImport18RawBootstrap::bootstrap_policy_loan_counter_scratch_data::<()>().unwrap()
            > OriginalImport18RawBootstrap::immutable_policy_loan_counter_scratch_data::<()>()
                .unwrap()
    );
    Ok(())
}

/// Compares every shape field without adding production traits for test assertions.
fn policy_shape_fields(
    shape: &crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
) -> [usize; 11] {
    let crate::retained_metadata::serialization_storage::OriginalSerializationStorageData {
        dom_and_canonical_scratch_bytes,
        retained_value_backing_bytes,
        projected_parser_requested_bytes,
        canonical_output_requested_bytes,
        serializer_temporary_requested_bytes,
        declared_counter_scratch_bytes,
        maximum_encoded_bytes,
        sequence_elements,
        sequence_containers,
        serialized_value_nodes,
        serialized_capacity_records,
    } = shape;
    [
        *dom_and_canonical_scratch_bytes,
        *retained_value_backing_bytes,
        *projected_parser_requested_bytes,
        *canonical_output_requested_bytes,
        *serializer_temporary_requested_bytes,
        *declared_counter_scratch_bytes,
        *maximum_encoded_bytes,
        *sequence_elements,
        *sequence_containers,
        *serialized_value_nodes,
        *serialized_capacity_records,
    ]
}

/// Compares the original birth loan with the independent retained-Value grammar.
fn assert_bootstrap_birth_wire(
    original: &OriginalImport18RawBootstrap,
    view: &PacketNativeImport18BootstrapTypedBirthView<'_>,
) -> Result<(), ProviderError> {
    use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::native_import18_bootstrap_birth_wire_data;
    use crate::retained_metadata::MetadataObserver;
    use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;

    let bodies = original.typed_bodies_data()?;
    let source = bodies.boot.source_binding_data();
    assert!(std::ptr::eq(view.source_binding_data(), source));
    let projected = view.serialization_data(usize::MAX).unwrap();

    // Only the independent oracle parses the retained raw body. The production
    // loan borrows its original typed fields and never allocates this DOM.
    let mut boot: Value = serde_json::from_slice(&original.bodies[2]).unwrap();
    let birth: Bytes = serde_json::from_value(boot["birth_id"].clone()).unwrap();
    let private_launch: Id = serde_json::from_value(boot["private_launch"].clone()).unwrap();
    let host: crucible_node_format::ContentRef =
        serde_json::from_value(boot["host_executable"].clone()).unwrap();
    let expected = native_import18_bootstrap_birth_wire_data(
        &birth,
        &private_launch,
        &host,
        &boot["source_birth"],
        &boot["expected_host_registration"],
    )?;
    assert_eq!(
        serde_json::to_value(view).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert_eq!(view.birth_id_data(), &birth);

    let source_birth = source.declaration_data().source_birth_data();
    let mut observer = MetadataObserver::new();
    observer.observe(view.birth_id_data()).unwrap();
    observer.observe(source_birth).unwrap();
    let actual = actual_serialization_storage_data(view, observer.finish(), usize::MAX).unwrap();
    let projected_fields = policy_shape_fields(&projected);
    let actual_fields = policy_shape_fields(&actual);
    // Counter implementations and custom formatter admission have independent
    // defining terms. All DOM, parser, output and population fields must agree.
    for index in [0, 1, 2, 3, 6, 7, 8, 9, 10] {
        assert_eq!(
            projected_fields[index], actual_fields[index],
            "shape field {index}"
        );
    }
    assert_eq!(
        projected.serializer_temporary_requested_bytes,
        Bytes::borrowed_serialization_temporary_bytes_data(source_birth.as_slice())
            .unwrap()
            .max(43),
    );
    let peak = projected.requested_total().unwrap();
    for restriction in [peak, peak + 4096] {
        assert_eq!(
            policy_shape_fields(&view.serialization_data(restriction).unwrap()),
            projected_fields
        );
    }
    assert!(view.serialization_data(peak - 1).is_err());
    assert!(view.serialization_data(1).is_err());
    assert!(
        OriginalImport18RawBootstrap::bootstrap_birth_loan_counter_scratch_data::<()>().unwrap()
            > OriginalImport18RawBootstrap::bootstrap_policy_loan_counter_scratch_data::<()>()
                .unwrap()
    );

    boot["birth_id"] = json!(Bytes::new(vec![0; 31]));
    let malformed: PacketNativeImport18PrivateBootWireData = serde_json::from_value(boot).unwrap();
    assert!(malformed.bootstrap_birth_wire_data().is_err());
    Ok(())
}

/// Checks all nine wire fields independently against the actual live SDK authority.
fn assert_bootstrap_native_registration(
    original: &OriginalImport18RawBootstrap,
    view: &PacketNativeImport18CurrentRegistrationView<'_>,
) -> Result<(), ProviderError> {
    use crate::reference_packet::service::complete_restore::import18::hello::{
        NATIVE_IMPORT18_CONNECTION_ID, native_import18_current_registration_view_data,
    };
    use crate::retained_metadata::MetadataObserver;
    use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;

    let projected = view.native_serialization_data(usize::MAX).unwrap();
    original.with_hello_authority_data(|authority| {
        assert_eq!(
            authority.connection_id().as_str(),
            NATIVE_IMPORT18_CONNECTION_ID
        );
        let expected = json!({
            "schema": "source-owned.packet-canonical-ack-registration/5",
            "role": "native",
            "connection_id": authority.connection_id(),
            "session_id": authority.session_id(),
            "incarnation_id": authority.incarnation_id(),
            "limits": authority.limits(),
            "features": authority.selected_features(),
            "extensions": authority.selected_extensions().unwrap(),
            "envelope_extensions": authority.envelope_extensions(),
        });
        assert_eq!(serde_json::to_value(view).unwrap(), expected);
        Ok(())
    })?;

    let actual =
        actual_serialization_storage_data(view, MetadataObserver::new().finish(), usize::MAX)
            .unwrap();
    let projected_fields = policy_shape_fields(&projected);
    let actual_fields = policy_shape_fields(&actual);
    for index in [0, 1, 2, 3, 4, 6, 7, 8, 9, 10] {
        assert_eq!(
            projected_fields[index], actual_fields[index],
            "shape field {index}"
        );
    }
    // The shared projection retains its original twenty-byte scalar reserve.
    assert_eq!(projected.serializer_temporary_requested_bytes, 20);
    let peak = projected.requested_total().unwrap();
    for restriction in [peak, peak + 4096] {
        assert_eq!(
            policy_shape_fields(&view.native_serialization_data(restriction).unwrap()),
            projected_fields
        );
    }
    assert!(view.native_serialization_data(peak - 1).is_err());
    assert!(view.native_serialization_data(1).is_err());
    assert!(
        OriginalImport18RawBootstrap::bootstrap_native_registration_loan_counter_scratch_data::<()>(
        )
        .unwrap()
            > OriginalImport18RawBootstrap::bootstrap_policy_loan_counter_scratch_data::<()>()
                .unwrap()
    );

    let controller = Id::new("original-controller").unwrap();
    original.with_hello_authority_data(|authority| {
        let controller_view =
            native_import18_current_registration_view_data(authority, Some(&controller))?;
        assert!(
            controller_view
                .native_serialization_data(usize::MAX)
                .is_err()
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn original_normalizations_keep_complete_and_refused_output_owners() {
    for case in [
        "initial_policy_kernel_normalizations_complete",
        "initial_policy_kernel_normalizations_reactive",
        "initial_policy_kernel_normalizations_missing_kernel",
        "initial_policy_kernel_normalizations_changed_cut",
        "initial_policy_kernel_normalizations_reject_construction",
        "initial_policy_kernel_normalizations_reject_policy",
        "initial_policy_kernel_normalizations_retain_birth",
        "initial_policy_kernel_normalizations_retain_kernel",
        "initial_policy_kernel_normalizations_retain_policy",
        "initial_policy_kernel_normalizations_retain_native",
        "initial_policy_kernel_normalizations_retain_host",
        "initial_policy_kernel_normalizations_expire_policy",
        "initial_policy_kernel_normalizations_revoke_native",
    ] {
        flight(case);
    }
}

#[test]
fn completed_hash_loans_check_the_actual_host_plan_and_original_live_sdk() {
    for suffix in [
        "complete",
        "reactive",
        "callback_refused",
        "loan_expired",
        "error_expired",
        "revoked",
        "contained",
        "changed_cut",
        "incomplete",
        "bad_schema",
        "bad_role",
        "bad_connection",
        "bad_session",
        "bad_incarnation",
        "bad_limits",
        "bad_features",
        "bad_extensions",
        "bad_keys",
        "extra_field",
        "missing_field",
    ] {
        flight(&format!(
            "initial_policy_kernel_normalizations_host_{suffix}"
        ));
    }
}

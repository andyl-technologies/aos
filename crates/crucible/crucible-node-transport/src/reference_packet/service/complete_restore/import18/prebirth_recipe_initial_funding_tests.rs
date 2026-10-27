//! Checks the real Initial producer using explicitly inert complete-recipe DATA.
//!
//! Only this child of the recipe module constructs the opaque test fixture. Its
//! phase partitions are synthetic; no full recipe producer, Source claim, native
//! process, escrow, Model, Hold or live Initial consumer is qualified here.

use super::*;
use crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures;
use crucible_node_format::Bytes;
use serde_json::{Value, json};

struct Operands {
    selected: PacketNativeImport18SelectedLaunchWireData,
    boot: PacketNativeImport18PrivateBootWireData,
    recipe: PacketNativeImport18PrebirthRecipeData,
    source: Vec<u8>,
    expected_host_registration: Value,
    private_launch: Id,
    host_executable: ContentRef,
}

impl Operands {
    fn new(reactive: bool) -> Self {
        let selected: PacketNativeImport18SelectedLaunchWireData =
            serde_json::from_value(inert_bootstrap_fixtures::initial_selected_launch(reactive))
                .unwrap();
        let launch = selected.launch_data();
        let source =
            canonical::canonical_json(&inert_bootstrap_fixtures::source_birth(launch)).unwrap();
        let mut boot = inert_bootstrap_fixtures::boot(1, json!({"actual": [1, "host"]}));
        boot["source_birth"]["declaration"]["source_birth"] = json!(Bytes::new(source.clone()));
        boot["source_birth"]["declaration"]["fresh_restore_allocation_selection"] = json!(null);
        boot["host_executable"] = serde_json::to_value(&launch.controller_executable).unwrap();
        let expected_host_registration = boot["expected_host_registration"].clone();
        let private_launch: Id = serde_json::from_value(boot["private_launch"].clone()).unwrap();
        let host_executable: ContentRef =
            serde_json::from_value(boot["host_executable"].clone()).unwrap();
        let boot: PacketNativeImport18PrivateBootWireData = serde_json::from_value(boot).unwrap();
        let declaration =
            native_import18_source_declaration_bank_view_data(&source, launch).unwrap();
        let construction = native_import18_initial_construction_data(
            launch,
            declaration,
            &expected_host_registration,
            &private_launch,
            &host_executable,
            usize::MAX / 16,
        )
        .unwrap();
        let launch_identity =
            derive_native_import18_launch_identity_data(launch, &private_launch, usize::MAX / 16)
                .unwrap();
        let mut wire: PacketNativeImport18PrebirthRecipeWireData =
            serde_json::from_value(inert_bootstrap_fixtures::recipe()).unwrap();
        let axes = construction
            .requested_storage_data()
            .map(|axis| U64::new(u64::try_from(axis).unwrap()));
        wire.fields.phases[PacketNativeImport18PrebirthPhase::Prepare.ordinal_data()] = axes;
        wire.fields.escrow = [U64::new(axes[0].get() + 4), axes[1], axes[2]];
        wire.fields.decoder_limits[9] = U64::new(u64::try_from(usize::MAX / 16).unwrap());
        wire.fields.selected_launch_identity = launch_identity.selected_launch_identity_data();
        wire.fields.private_launch_identity = launch_identity.private_launch_identity_data();
        wire.fields.nonce = native_import18_mapping_nonce_data(&[23; 32]);
        wire.fields.lease_identity = native_import18_mapping_lease_identity_data(
            &launch_identity,
            &wire.fields.nonce,
            wire.fields.generation,
        )
        .unwrap();
        wire.validate_data().unwrap();

        Self {
            selected,
            boot,
            source,
            expected_host_registration,
            private_launch,
            host_executable,
            recipe: PacketNativeImport18PrebirthRecipeData {
                fields: wire.fields,
            },
        }
    }

    fn inputs(&self) -> PacketNativeImport18InitialFundingInputs<'_, Value> {
        PacketNativeImport18InitialFundingInputs {
            recipe: &self.recipe,
            launch: self.selected.launch_data(),
            declaration: native_import18_source_declaration_bank_view_data(
                &self.source,
                self.selected.launch_data(),
            )
            .unwrap(),
            expected_host_registration: &self.expected_host_registration,
            private_launch: &self.private_launch,
            host_executable: &self.host_executable,
            nonce: &self.recipe.fields.nonce,
            generation: self.recipe.fields.generation,
        }
    }
}

#[test]
fn initial_producer_matches_independent_native_formula_and_exact_parent_credit() {
    for reactive in [false, true] {
        let operands = Operands::new(reactive);
        let inputs = operands.inputs();
        let cost =
            native_import18_initial_funding_producer_construction_data(&inputs, usize::MAX / 16)
                .unwrap();
        let peak = cost.into_iter().sum();
        assert_eq!(
            native_import18_initial_funding_producer_construction_data(&inputs, peak).unwrap(),
            cost
        );
        assert!(
            native_import18_initial_funding_producer_construction_data(&inputs, peak - 1).is_err()
        );
        assert!(derive_native_import18_initial_funding_data(&inputs, peak - 1).is_err());

        let initial = derive_native_import18_initial_funding_data(&inputs, peak).unwrap();
        let native = initial_construction_from_wire_data(
            &operands.selected,
            &operands.boot,
            usize::MAX / 16,
        )
        .unwrap();
        let row = initial.row_data();
        assert_eq!(
            [
                row.retained_requested_bytes.get(),
                row.maximum_simultaneous_transient_bytes.get(),
                row.declared_counter_scratch_bytes.get(),
            ],
            native
                .requested_storage_data()
                .map(|axis| u64::try_from(axis).unwrap())
        );
        assert_eq!(
            initial.body_maximums_data().map(|value| value.get()),
            native
                .maximum_encoded_bytes_data()
                .map(|axis| u64::try_from(axis).unwrap())
        );
        assert_eq!(
            initial.recipe_identity_data(),
            operands.recipe.identity_data()
        );
        let launch = derive_native_import18_launch_identity_data(
            inputs.launch,
            inputs.private_launch,
            usize::MAX / 16,
        )
        .unwrap();
        initial
            .authenticate_operands_data(&operands.recipe, &launch, inputs.nonce, inputs.generation)
            .unwrap();
        assert!(!std::mem::needs_drop::<
            PacketNativeImport18InitialFundingData,
        >());
    }
}

#[test]
fn initial_producer_refuses_each_foreign_birth_and_launch_operand() {
    let operands = Operands::new(false);
    let other_nonce = [42; 32];
    let other_launch = Id::new("different-private-launch").unwrap();
    let mut other_executable = operands.host_executable.clone();
    other_executable.hash.digest = "f".repeat(64);

    let mut inputs = operands.inputs();
    inputs.nonce = &other_nonce;
    assert!(derive_native_import18_initial_funding_data(&inputs, usize::MAX / 16).is_err());
    inputs = operands.inputs();
    inputs.generation = U64::new(inputs.generation.get() + 1);
    assert!(derive_native_import18_initial_funding_data(&inputs, usize::MAX / 16).is_err());
    inputs = operands.inputs();
    inputs.private_launch = &other_launch;
    assert!(derive_native_import18_initial_funding_data(&inputs, usize::MAX / 16).is_err());
    inputs = operands.inputs();
    inputs.host_executable = &other_executable;
    assert!(derive_native_import18_initial_funding_data(&inputs, usize::MAX / 16).is_err());
}

#[test]
fn initial_producer_refuses_a_coherently_rehashed_foreign_mapping_commitment() {
    for reactive in [false, true] {
        let operands = Operands::new(reactive);
        let mut recipe = operands.recipe;
        recipe.fields.lease_identity[0] ^= 1;
        recipe.fields.identity = recipe
            .announcement_data()
            .reconstructed_identity_data(usize::MAX / 16)
            .unwrap();
        recipe
            .announcement_data()
            .authenticate_identity_data(usize::MAX / 16)
            .unwrap();
        let mut inputs = operands.inputs();
        inputs.recipe = &recipe;
        let launch = derive_native_import18_launch_identity_data(
            inputs.launch,
            inputs.private_launch,
            usize::MAX / 16,
        )
        .unwrap();

        assert!(
            recipe
                .authenticate_birth_operands_data(
                    inputs.nonce,
                    inputs.generation,
                    &launch.selected_launch_identity_data(),
                    &launch.private_launch_identity_data(),
                )
                .is_err()
        );
        assert!(derive_native_import18_initial_funding_data(&inputs, usize::MAX / 16).is_err());
    }
}

#[test]
fn initial_producer_cannot_borrow_a_later_phase_partition() {
    let operands = Operands::new(false);
    for axis in 0..3 {
        let mut recipe = operands.recipe;
        let original = recipe.fields.phases[0][axis];
        recipe.fields.phases[0][axis] = U64::new(original.get() - 1);
        recipe.fields.phases[1][axis] = if axis == 0 { U64::new(2) } else { original };
        recipe.announcement_data().validate_data().unwrap();
        let mut inputs = operands.inputs();
        inputs.recipe = &recipe;

        assert!(derive_native_import18_initial_funding_data(&inputs, usize::MAX / 16).is_err());
    }
}

#[test]
fn initial_producer_leaves_worker_bytes_opaque_and_native_checks_them_separately() {
    let operands = Operands::new(false);
    let original =
        derive_native_import18_initial_funding_data(&operands.inputs(), usize::MAX / 16).unwrap();
    let opaque = vec![255; operands.source.len()];
    let mut inputs = operands.inputs();
    inputs.declaration =
        native_import18_source_declaration_bank_view_data(&opaque, inputs.launch).unwrap();

    let projected = derive_native_import18_initial_funding_data(&inputs, usize::MAX / 16).unwrap();

    assert_eq!(projected.row_data(), original.row_data());
    assert_eq!(
        projected.body_maximums_data(),
        original.body_maximums_data()
    );
    let wire: PacketNativeImport18SourceDeclarationWireData = serde_json::from_value(json!({
        "schema": NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA,
        "source_birth": Bytes::new(opaque.clone()),
        "fresh_restore_allocation_selection": null,
    }))
    .unwrap();
    assert!(wire.authenticate_launch_data(inputs.launch).is_err());
}

#[test]
fn initial_producer_recomputes_actual_launch_and_registration_demand() {
    let operands = Operands::new(false);
    let mut changed = inert_bootstrap_fixtures::initial_selected_launch(false);
    changed["launch"]["admission_token"] = json!(Bytes::new(vec![42; 4096]));
    let changed: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(changed).unwrap();
    let mut inputs = operands.inputs();
    inputs.launch = changed.launch_data();
    assert!(derive_native_import18_initial_funding_data(&inputs, usize::MAX / 16).is_err());

    let registration = json!({"larger_original_registration": "x".repeat(524288)});
    inputs = operands.inputs();
    inputs.expected_host_registration = &registration;
    assert!(derive_native_import18_initial_funding_data(&inputs, usize::MAX / 16).is_err());
}

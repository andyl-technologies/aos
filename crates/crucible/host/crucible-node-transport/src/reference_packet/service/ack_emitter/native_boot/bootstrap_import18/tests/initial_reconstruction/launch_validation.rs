//! Exercises full pure launch validation under actual inherited bootstrap custody.
//!
//! These model admission callbacks grant no genuine Source/Birth funding. Valid
//! Producer/Reactive configuration DTOs create no runtime model or native grant.

use super::super::super::launch_validation::OriginalImport18LaunchValidationAdmission;
use super::*;
use crate::reference_packet::connected::{PacketConnectedDefinition, PacketInputConnection};
use crate::reference_packet::{PacketEvent, PacketProgramDefinition};
use crucible_node_format::{Phase, Position, U64, WorldBinding};
use std::cell::Cell;

pub(super) fn prepare_selected(case: &str, selected: &mut Value) {
    let bytes: Bytes =
        serde_json::from_value(selected["launch"]["initial_coordinator"]["bytes"].clone()).unwrap();
    let installation: crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation =
        serde_json::from_slice(bytes.as_slice()).unwrap();
    let reactive = case == "initial_launch_validation_reactive";
    let member = usize::from(reactive);
    selected["launch"]["selection"] = json!(installation.participants[member]);
    if reactive {
        let world: WorldBinding =
            serde_json::from_value(installation.template["world"].clone()).unwrap();
        let node = &installation.participants[member].realization.descriptors[0].id;
        let connections: Vec<_> = world
            .connections
            .iter()
            .filter(|connection| &connection.consumer.node_id == node)
            .map(|connection| PacketInputConnection {
                id: connection.id.clone(),
                policy: connection.policy_ref.clone(),
                producer: connection.producer.clone(),
                consumer: connection.consumer.clone(),
                delay_ps: connection.minimum_latency_ps,
            })
            .collect();
        let output = world
            .connections
            .iter()
            .find(|connection| &connection.producer.node_id == node)
            .map(|connection| connection.producer.clone());
        selected["launch"]["program"] = json!({
            "kind": "reactive",
            "program": PacketConnectedDefinition {
                schema: "source-owned.packet-connected-program/4".into(), connections, output,
            },
        });
    } else {
        let program = PacketProgramDefinition {
            schema: "source-owned.packet-program.v1".into(),
            events: vec![
                PacketEvent {
                    id: Id::new("private-callback-0").unwrap(),
                    evaluation: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                    completion: Position::new(U64::new(4), U64::new(0), Phase::Reaction),
                    payload: None,
                },
                PacketEvent {
                    id: Id::new("packet-callback-0").unwrap(),
                    evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
                    completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
                    payload: Some(Bytes::new(b"original-producer".to_vec())),
                },
            ],
        };
        selected["launch"]["program"] = json!({"kind": "producer", "program": program});
    }
    let launch: PacketNativeImport18SelectedLaunchWireData =
        serde_json::from_value(selected.clone()).unwrap();
    launch.launch_data().validate().unwrap();

    if case == "initial_launch_validation_invalid_model" {
        selected["launch"]["program"]["program"]["events"]
            .as_array_mut()
            .unwrap()
            .pop();
    }
    if case == "initial_launch_validation_invalid_selection" {
        selected["launch"]["selection"]["provider"]["implementation"]["implementation_id"] =
            json!("changed-native-implementation");
    }
}

/// Funds the complete valid DTO fixture from its independently derived initial row.
///
/// The other four inert phase partitions and the independent 256 MiB policy
/// remain unchanged. These announcements still cannot construct an opaque Recipe.
pub(super) fn fund_initial_partition(values: &mut [Value; 3], row: [usize; 3]) {
    let recipe = &mut values[0];
    recipe["phases"][0] = json!(row.map(|axis| axis.to_string()));
    let mut escrow = [0usize; 3];
    for phase in recipe["phases"].as_array().unwrap() {
        let axes: [String; 3] = serde_json::from_value(phase.clone()).unwrap();
        let axes = axes.map(|axis| axis.parse::<usize>().unwrap());
        escrow[0] = escrow[0].checked_add(axes[0]).unwrap();
        escrow[1] = escrow[1].max(axes[1]);
        escrow[2] = escrow[2].max(axes[2]);
    }
    assert!(escrow.into_iter().sum::<usize>() <= typed::bounds().requested_peak);
    recipe["escrow"] = json!(escrow.map(|axis| axis.to_string()));
    let identity =
        serde_json::from_value::<PacketNativeImport18PrebirthRecipeWireData>(recipe.clone())
            .unwrap()
            .reconstructed_identity_data(typed::bounds().requested_peak)
            .unwrap();
    recipe["identity"] = json!(identity);
    values[1]["prebirth_recipe_identity"] = json!(identity);
    values[2]["source_birth"]["prebirth_recipe"] = values[0].clone();
}

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    retained: usize,
}

impl OriginalImport18LaunchValidationAdmission for Admission<'_> {
    fn construct_data(
        &self,
        owner: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert_eq!(owner.launch_validation.row_data(), Some(row));
        assert_eq!(row[0], 0);
        assert!(row[1] > 0 && row[2] > 0);
        assert_eq!(owner.retained_requested_bytes().unwrap(), self.retained);
        if self.case == "initial_launch_validation_construct_refused" {
            return Err(ProviderError::Conflict("launch construction refused"));
        }
        if self.case == "initial_launch_validation_construct_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn finish_data(&self, owner: &OriginalImport18RawBootstrap) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(2), 1);
        assert_eq!(owner.retained_requested_bytes().unwrap(), self.retained);
        if self.case == "initial_launch_validation_finish_refused" {
            return Err(ProviderError::Conflict("launch census refused"));
        }
        if self.case == "initial_launch_validation_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    let retained = owner.retained_requested_bytes().unwrap();
    let pointers = owner.bodies.each_ref().map(|body| body.as_ptr());
    let shared = std::rc::Rc::as_ptr(owner.parsed.shared_launch_data().unwrap());
    assert!(owner.with_validated_launch_data(|_| Ok(())).is_err());
    if case == "initial_launch_validation_incomplete" {
        owner.initial_reconstructed = false;
    }
    if case == "initial_launch_validation_before_expired" {
        std::thread::sleep(Duration::from_secs(5));
    }
    let admission = Admission {
        case,
        calls: Cell::new(0),
        retained,
    };

    let outcome = owner.validate_launch_data(&admission);

    let success = matches!(
        case,
        "initial_launch_validation_complete"
            | "initial_launch_validation_reactive"
            | "initial_launch_validation_callback_refused"
            | "initial_launch_validation_loan_expired"
            | "initial_launch_validation_substituted_cut"
    );
    if success {
        outcome.unwrap();
        assert_eq!(admission.calls.get(), 2);
        assert_eq!(
            owner
                .with_validated_launch_data(|launch| Ok(std::ptr::from_ref(launch)))
                .unwrap(),
            std::ptr::from_ref(owner.typed_bodies_data().unwrap().launch.launch_data())
        );
        if case == "initial_launch_validation_callback_refused" {
            assert!(
                owner
                    .with_validated_launch_data::<()>(|_| Err(ProviderError::Conflict(
                        "launch inspection refused"
                    )))
                    .is_err()
            );
            owner.with_validated_launch_data(|_| Ok(())).unwrap();
        }
        if case == "initial_launch_validation_substituted_cut" {
            let original = owner.cut;
            owner.cut = OperationalDeadline::after(Duration::from_secs(3)).unwrap();
            assert!(owner.with_validated_launch_data(|_| Ok(())).is_err());
            owner.cut = original;
            owner.with_validated_launch_data(|_| Ok(())).unwrap();
        }
        if case == "initial_launch_validation_loan_expired" {
            assert!(
                owner
                    .with_validated_launch_data(|_| {
                        std::thread::sleep(Duration::from_secs(5));
                        Ok(())
                    })
                    .is_err()
            );
            assert!(owner.with_validated_launch_data(|_| Ok(())).is_err());
        }
    } else {
        assert!(outcome.is_err(), "{case}");
        assert!(owner.with_validated_launch_data(|_| Ok(())).is_err());
        if matches!(
            case,
            "initial_launch_validation_invalid_model"
                | "initial_launch_validation_invalid_selection"
        ) {
            assert_eq!(admission.calls.get(), 2);
        }
    }
    let calls = admission.calls.get();
    assert!(owner.validate_launch_data(&admission).is_err());
    assert_eq!(admission.calls.get(), calls);
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(owner.bodies.each_ref().map(|body| body.as_ptr()), pointers);
    assert_eq!(
        std::rc::Rc::as_ptr(owner.parsed.shared_launch_data().unwrap()),
        shared
    );
    assert!(owner.hello_selection.is_none());
    assert!(owner.inputs.is_empty_data());
}

#[test]
fn full_launch_validation_keeps_original_custody_without_installing_a_model() {
    for case in [
        "initial_launch_validation_complete",
        "initial_launch_validation_reactive",
        "initial_launch_validation_invalid_model",
        "initial_launch_validation_invalid_selection",
        "initial_launch_validation_incomplete",
        "initial_launch_validation_before_expired",
        "initial_launch_validation_construct_refused",
        "initial_launch_validation_construct_expired",
        "initial_launch_validation_finish_refused",
        "initial_launch_validation_finish_expired",
        "initial_launch_validation_callback_refused",
        "initial_launch_validation_substituted_cut",
        "initial_launch_validation_loan_expired",
    ] {
        flight(case);
    }
}

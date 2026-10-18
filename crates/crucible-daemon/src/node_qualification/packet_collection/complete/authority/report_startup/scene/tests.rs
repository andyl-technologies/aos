//! Exercises actual complete-scene owner staging without constructing a Child.
//!
//! Fixtures perform real file/executable measurements, entropy reads, socket
//! binds/pairs and bounded eventfd setup. No native executable, thread, control
//! connection, SDK constructor, Ready receipt or runtime activation is started.

use super::*;
use crate::node_qualification::packet_collection::complete::tests::POSITIVE_STARTUP_SETUP_MEMORY_BYTES;
use crucible::node_contract::SavedRuntimeActivation;
use crucible_node_contract::U64;
use std::{os::unix::net::UnixStream, time::Duration};

type Fixture = (
    crate::node_qualification::packet_collection::complete::tests::Scene,
    Rc<RefCell<PacketCompleteReportStartupHolder>>,
    Option<PacketCompleteOriginalSceneInputs>,
);

fn fixture() -> Fixture {
    let (scene, original) =
        crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
    // Use the shared positive setup policy without changing production limits.
    original.borrow_mut().resources.memory_bytes = U64::new(POSITIVE_STARTUP_SETUP_MEMORY_BYTES);
    let content = Rc::new(
        crate::node_qualification::packet_collection::complete::tests::report_startup_content_data(
            &scene,
        )
        .clone(),
    );
    let held = original.borrow();
    let mut registry = CnpSemanticRegistry::new(held.authority.clone(), 3).unwrap();
    let roles = std::array::from_fn(|member| {
        Some(
            registry
                .install_complete_packet_for_conformance(
                    held.authority.roster.sources[member].clone(),
                    held.authority.clone(),
                    &held.plan,
                )
                .unwrap(),
        )
    });
    let saved: SavedRuntimeActivation =
        serde_json::from_value(held.authority.roster.coordinator.template["activation"].clone())
            .unwrap();
    let activation = ActivationRecord {
        generation: saved.generation,
        activation_id: saved.activation_id,
        world_binding_hash: saved.world_binding_hash,
        owners: saved.owners,
        boundary: saved.boundary,
    };
    let inputs = PacketCompleteOriginalSceneInputs {
        supervisor: PacketWorldHostSupervisor::new_complete_original()
            .unwrap()
            .into(),
        activation,
        runtime_limits: RuntimeLimits {
            maximum_nodes: 4,
            maximum_owners: 4,
            maximum_operations: 64,
            maximum_retained_outputs: 64,
        },
        content: Some([Rc::clone(&content), Rc::clone(&content), content]),
        launches: std::array::from_fn(|member| {
            let (reader, writer) = UnixStream::pair().unwrap();
            let measurement = &held.authority.graph_policy.measurements()[member].peer;
            Some(PacketCompleteNativeLaunchInputs {
                executable_path: measurement.path.clone(),
                executable: measurement.content.clone(),
                directory: held.authority.directories[member].clone(),
                socket: held.authority.directories[member].join("control.sock"),
                slot: None,
                bootstrap_reader: Some(reader),
                bootstrap_writer: Some(writer),
                write_watchdog: Duration::from_secs(1),
            })
        }),
        planned_query_ids: std::array::from_fn(|member| {
            Some(Id::new(format!("scene-query-{member}")).unwrap())
        }),
        admit_ids: std::array::from_fn(|member| Id::new(format!("scene-admit-{member}")).unwrap()),
        registry,
        roles,
    };
    drop(held);
    (scene, original, Some(inputs))
}

#[test]
fn actual_scene_stages_same_supervised_owners_before_report_or_child() {
    let (_fixture, original, mut incoming) = fixture();
    let before = {
        let held = original.borrow();
        held.authority
            .roster
            .sources
            .each_ref()
            .map(|source| source.original_report_startup_audit_data().unwrap())
    };

    PacketCompleteReportStartupHolder::stage_original_scene_into(&original, &mut incoming).unwrap();

    assert!(incoming.is_none());
    let held = original.borrow();
    let scene = held.original_scene.get().unwrap().borrow();
    assert!(scene.staged);
    assert!(scene.reservation_attempted.get());
    assert!(scene.runtime_slot.is_some());
    assert!(scene.journal_slots.iter().all(Option::is_some));
    assert!(scene.inputs.launches.iter().all(Option::is_none));
    assert!(held.host_sdk_content.get().is_some());
    assert!(!held.attempted.get());
    assert!(!held.native_attempted.get());
    assert!(!held.host_sdk_attempted.get());
    assert!(!scene.launched.get());
    assert!(held.authority.roster.current_native().is_err());
    for (source, before) in held.authority.roster.sources.iter().zip(before) {
        let after = source.original_report_startup_audit_data().unwrap();
        assert_eq!(before.encoded_birth_digest, after.encoded_birth_digest);
        assert_eq!(before.encoded_birth_capacity, after.encoded_birth_capacity);
        assert!(!after.boot_started);
        assert!(!after.finalization_present);
    }
}

#[test]
fn actual_scene_reservation_exact_and_one_short_preserve_original_banks() {
    for short in [false, true] {
        let (_fixture, original, mut incoming) = fixture();
        PacketCompleteReportStartupHolder::retain_original_scene_data(&original, &mut incoming)
            .unwrap();
        let peak = {
            let held = original.borrow();
            PacketCompleteReportStartupHolder::preflight_original_scene_reservation_data(
                &original, &held,
            )
            .unwrap()
        };
        original.borrow_mut().resources.memory_bytes = U64::new((peak - usize::from(short)) as u64);

        let result = PacketCompleteReportStartupHolder::reserve_original_scene_data(&original);

        assert_eq!(result.is_err(), short);
        assert!(incoming.is_none());
        let held = original.borrow();
        let scene = held.original_scene.get().unwrap().borrow();
        assert!(scene.reservation_attempted.get());
        assert_eq!(scene.staged, !short);
        assert_eq!(scene.runtime_slot.is_some(), !short);
        assert_eq!(scene.journal_slots.iter().all(Option::is_none), short);
        if short {
            assert!(scene.inputs.content.is_some());
            assert!(
                scene
                    .inputs
                    .launches
                    .iter()
                    .all(|input| input.as_ref().is_some_and(|input| input.slot.is_none()))
            );
            assert!(held.host_sdk_content.get().is_none());
        }
        drop(scene);
        drop(held);
        assert!(PacketCompleteReportStartupHolder::reserve_original_scene_data(&original).is_err());
    }
}

#[test]
fn actual_scene_foreign_creator_refuses_before_consuming_busy_inputs() {
    let (_fixture, original, mut incoming) = fixture();
    let process = original.borrow().process;
    original.borrow_mut().process = process.wrapping_add(1);
    let held = original.borrow();
    let _native = held.native_launches.borrow_mut();

    assert!(matches!(
        PacketCompleteReportStartupHolder::stage_original_scene_into(&original, &mut incoming),
        Err(RuntimeError::ForeignAuthority),
    ));

    assert!(incoming.is_some());
    assert!(held.original_scene.get().is_none());
}

#[test]
fn actual_staged_scene_retirement_revokes_future_actions_without_child() {
    let (_fixture, original, mut incoming) = fixture();
    PacketCompleteReportStartupHolder::stage_original_scene_into(&original, &mut incoming).unwrap();

    PacketCompleteReportStartupHolder::retire_original_scene(&original).unwrap();

    let held = original.borrow();
    assert!(held.original_scene_retired.get());
    assert!(
        held.original_scene
            .get()
            .unwrap()
            .borrow()
            .runtime_slot
            .is_none()
    );
    assert!(held.host_sdk_content.get().is_some());
    assert!(!held.attempted.get());
    drop(held);
    assert!(PacketCompleteReportStartupHolder::launch_original_scene(&original).is_err());
    assert!(
        PacketCompleteReportStartupHolder::complete_original_scene_initial_lifecycle(&original)
            .is_err()
    );
    PacketCompleteReportStartupHolder::retire_original_scene(&original).unwrap();
    assert!(matches!(
        PacketCompleteReportStartupHolder::drive_original_scene_reclamation(&original, 1).unwrap(),
        std::task::Poll::Ready(Ok(_)),
    ));
}

#[test]
fn bounded_daemon_refusal_preserves_public_display_bytes() {
    for message in [
        super::initial_lifecycle::INITIAL_CALLBACK_REFUSAL,
        "complete original packet collecting scope unavailable",
    ] {
        let expected = QualificationError::Refused(message).to_string();
        assert_eq!(
            qualification_reason(QualificationError::Refused(message)),
            expected
        );
        assert_eq!(
            operation_error(QualificationError::Refused(message)).reason,
            expected
        );
        assert_eq!(
            evidence_error(QualificationError::Refused(message)).message,
            expected
        );
    }
}

#[test]
fn unlaunched_initial_member_refuses_without_spending_its_window() {
    let (_fixture, original, mut incoming) = fixture();
    PacketCompleteReportStartupHolder::stage_original_scene_into(&original, &mut incoming).unwrap();

    for selected in 0..=3 {
        assert!(matches!(
            PacketCompleteReportStartupHolder::complete_retained_host_initial_lifecycle_member(
                &original, selected,
            ),
            Err(RuntimeError::OwnerUnavailable),
        ));
    }

    let held = original.borrow();
    let scene = held.original_scene.get().unwrap().borrow();
    assert!(!scene.launched.get());
    assert!(scene.initial_attempted.iter().all(|flag| !flag.get()));
    assert!(scene.initial_in_flight.iter().all(|flag| !flag.get()));
    assert!(scene.initial_completed.iter().all(|flag| !flag.get()));
    assert!(scene.windows.iter().all(|window| window.get().is_none()));
    assert!(!held.native_attempted.get());
}

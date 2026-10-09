//! Actual native custody after an injected late recording-constructor refusal.
//!
//! The fault applies to host preparation, after an earlier real native wrapper
//! succeeded. It tests complete original-world containment without claiming
//! native fidelity qualification from the injected fault.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::{
    task::{Context, Poll, Waker},
    time::Instant,
};

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE pointing to the current source-built native executable"]
fn actual_late_recording_refusal_keeps_earlier_wrapper_and_every_original_native_owner() {
    let executable = PathBuf::from(std::env::var("CRUCIBLE_REFERENCE_DEVICE").unwrap());
    let temporary = tempfile::tempdir().unwrap();
    let mut catalog = InstalledNodeCatalog::new(
        executable.clone(),
        measure_executable(&executable).unwrap(),
        temporary.path().to_owned(),
        Duration::from_secs(5),
        1,
    )
    .unwrap();
    let selections = ["first", "second"].map(|node| InstalledNodeSelection {
        node: id(node),
        owner: id(&format!("{node}-owner")),
        kind: InstalledNodeKind::ReferenceDevice {
            quantum_ps: U64::new(50),
            host_budget_ns: U64::new(20_000_000),
        },
    });
    let scenario = catalog.scenario(&selections).unwrap();
    let configuration = NodeRunConfiguration {
        format: "crucible.node-run-configuration".into(),
        version: 1,
        horizon_ps: U64::new(50),
        maximum_rounds: U64::new(8),
    };
    let execution = ExecutionId::from_bytes([93; 16]).unwrap();
    let mut recorder = ReferenceRecorder {
        selections: &selections,
        scenario: &scenario,
        configuration: &configuration,
        attempt: id(&format!("observed/{}", execution_text(execution))),
        limits: TranscriptLimits {
            maximum_records: U64::new(8),
            maximum_record_bytes: U64::new(1024 * 1024),
            maximum_total_bytes: U64::new(16 * 1024 * 1024),
        },
        handles: BTreeMap::new(),
        preparation_fault: Some(RecordingPreparationFault {
            node: id("second"),
            original_activation: None,
        }),
    };
    let artifacts = catalog.artifacts.clone();

    let result = catalog.prepare_world_with_source(
        &selections,
        scenario.clone(),
        execution,
        PreparationSource::default(),
        &artifacts,
        Some(&mut recorder),
    );

    let error = match result {
        Ok(_) => panic!("injected late host preparation refusal was ignored"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("injected recording preparation custody fault")
    );
    assert_eq!(recorder.handles.keys().collect::<Vec<_>>(), [&id("first")]);
    let original = recorder
        .preparation_fault
        .as_ref()
        .unwrap()
        .original_activation
        .as_ref()
        .unwrap();
    assert_eq!(
        original.world_binding_hash,
        scenario.world.identity().unwrap()
    );
    assert_eq!(
        original.activation_id,
        id(&format!("activation/{}", execution_text(execution)))
    );
    assert_eq!(
        original
            .owners
            .iter()
            .map(|owner| owner.owner.clone())
            .collect::<Vec<_>>(),
        [id("first-owner"), id("second-owner")]
    );
    assert_eq!(original.generation, U64::new(1));
    assert_eq!(
        original.boundary,
        Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
    );
    assert_eq!(catalog.custody().reserved_worlds(), 1);
    assert_eq!(catalog.custody().retained_worlds(), 1);
    assert!(
        recorder.handles[&id("first")].finish().is_err(),
        "no semantic interaction ran before refusal"
    );

    let mut context = Context::from_waker(Waker::noop());
    let deadline = Instant::now() + Duration::from_secs(10);
    while catalog.custody().reserved_worlds() != 0 {
        if let Poll::Ready(Err(error)) = catalog.custody().poll_reclamation(&mut context) {
            panic!("original native world reclamation failed: {error:?}");
        }
        assert!(
            Instant::now() < deadline,
            "original native children were not positively reclaimed"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(catalog.custody().retained_worlds(), 0);
}

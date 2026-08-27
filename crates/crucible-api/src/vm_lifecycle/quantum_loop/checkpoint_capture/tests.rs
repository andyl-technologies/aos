//! Exact-checkpoint capture ownership regressions.

use super::*;

fn boundary_error(message: &str) -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: String::from(message),
    }
}

#[test]
fn preparation_is_all_or_nothing_before_live_capture() {
    let source = crucible::crash_restart_scenario()
        .unwrap_or_else(|error| panic!("built-in scenario should validate: {error}"))
        .scenario;
    let configuration = Configuration::genesis(source.scenario_def());
    let node_a = NodeId {
        name: String::from("node-a"),
    };
    let node_b = NodeId {
        name: String::from("node-b"),
    };
    let node_icounts = BTreeMap::from([
        (node_a.clone(), crucible::Icount { retired: 11 }),
        (node_b.clone(), crucible::Icount { retired: 13 }),
    ]);
    let boundaries = || {
        vec![
            (
                node_a.clone(),
                11,
                VirtualTime { ticks: 17 },
                ProductionNodeServiceState::Running,
            ),
            (
                node_b.clone(),
                13,
                VirtualTime { ticks: 19 },
                ProductionNodeServiceState::PoweredOff,
            ),
        ]
    };
    let indexes = BTreeMap::from([(node_a.clone(), 0), (node_b.clone(), 1)]);
    let directories = BTreeMap::from([
        (node_a.clone(), PathBuf::from("generation-a")),
        (node_b.clone(), PathBuf::from("generation-b")),
    ]);
    let staging = tempfile::tempdir()
        .unwrap_or_else(|error| panic!("checkpoint staging should build: {error}"));

    let prepared = prepare_exact_checkpoint_targets(
        &configuration,
        VirtualTime { ticks: 23 },
        &node_icounts,
        boundaries(),
        &indexes,
        &directories,
        staging.path(),
    )
    .unwrap_or_else(|error| panic!("every target should prepare: {error}"));
    assert_eq!(prepared.len(), 2);
    assert_eq!(prepared[0].node, node_a);
    assert_eq!(prepared[0].checkpoint.node_icounts, node_icounts);
    assert_eq!(
        prepared[1].staged_vmstate,
        staging.path().join("node-1-vmstate.qcow2")
    );

    let incomplete_directories = BTreeMap::from([(node_a.clone(), PathBuf::from("generation-a"))]);
    let error = prepare_exact_checkpoint_targets(
        &configuration,
        VirtualTime { ticks: 23 },
        &node_icounts,
        boundaries(),
        &indexes,
        &incomplete_directories,
        staging.path(),
    )
    .err()
    .unwrap_or_else(|| panic!("a missing later target owner should fail preparation"));
    assert!(error.to_string().contains("node-b"));
}

#[test]
fn cleanup_attempts_every_capture_in_reverse_order() {
    #[derive(Debug, PartialEq, Eq)]
    struct Capture {
        id: u8,
        pending: bool,
    }
    let mut captures = vec![
        Capture {
            id: 1,
            pending: true,
        },
        Capture {
            id: 2,
            pending: true,
        },
        Capture {
            id: 3,
            pending: true,
        },
    ];
    let mut observed = Vec::new();
    let error = match cleanup_exact_captures_with(
        &mut captures,
        |capture| {
            observed.push(capture.id);
            if capture.id == 3 || capture.id == 1 {
                Err(capture.id)
            } else {
                Ok(())
            }
        },
        |capture| capture.pending = false,
        |capture| capture.pending,
    ) {
        Ok(()) => panic!("the first reverse-order cleanup error should survive"),
        Err(error) => error,
    };

    assert_eq!(observed, [3, 2, 1]);
    assert_eq!(error, 3);
    assert_eq!(
        captures,
        [
            Capture {
                id: 1,
                pending: true
            },
            Capture {
                id: 3,
                pending: true
            }
        ]
    );
}

#[test]
fn publication_registry_retains_only_durable_or_indeterminate_owners() {
    let configuration = ContentHash::from_bytes(b"configuration");
    let identity = ContentHash::from_bytes(b"checkpoint");

    let mut publications =
        BTreeMap::from([(configuration, ExactCheckpointPublicationState::Preparing)]);
    let committed =
        match finish_exact_checkpoint_transaction(&mut publications, configuration, Ok(identity)) {
            Ok(committed) => committed,
            Err(error) => panic!("publication should commit: {error}"),
        };
    assert_eq!(committed, identity);
    assert!(matches!(
        publications.get(&configuration),
        Some(ExactCheckpointPublicationState::Published(observed)) if *observed == identity
    ));

    publications.insert(configuration, ExactCheckpointPublicationState::Preparing);
    assert!(
        finish_exact_checkpoint_transaction(
            &mut publications,
            configuration,
            Err(ExactCheckpointTransactionError::Unpublished(
                boundary_error("unpublished",)
            )),
        )
        .is_err()
    );
    assert!(!publications.contains_key(&configuration));

    publications.insert(configuration, ExactCheckpointPublicationState::Preparing);
    assert!(
        finish_exact_checkpoint_transaction(
            &mut publications,
            configuration,
            Err(ExactCheckpointTransactionError::Indeterminate {
                identity: Some(identity),
                captures: Vec::new(),
                source: boundary_error("indeterminate"),
            }),
        )
        .is_err()
    );
    assert!(matches!(
        publications.get(&configuration),
        Some(ExactCheckpointPublicationState::PublicationIndeterminate(observed))
            if *observed == identity
    ));

    publications.insert(configuration, ExactCheckpointPublicationState::Preparing);
    assert!(
        finish_exact_checkpoint_transaction(
            &mut publications,
            configuration,
            Err(ExactCheckpointTransactionError::Indeterminate {
                identity: None,
                captures: Vec::new(),
                source: boundary_error("cleanup pending"),
            }),
        )
        .is_err()
    );
    assert!(matches!(
        publications.get(&configuration),
        Some(ExactCheckpointPublicationState::CleanupPending(captures))
            if captures.is_empty()
    ));
}

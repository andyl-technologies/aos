//! Real datagram and file controls for the original pre-Compute journal.
//!
//! Source facts and consumed replies are explicitly modeled. The tests issue no
//! native epoch, actual source ACK, common prepared owner or execution permission.

// SPDX-License-Identifier: Apache-2.0

use super::controls::{position, prefix_original};
use super::*;
use crucible_protocol::node_control::{
    NativeChannel, NativeControlEdition, NativeFrame, NativeInitializationReceipt,
    NativeInitializationStatus, NativePrefixPreparation, NativePrefixPreparationFacts,
    NativePrefixPreparationObservation,
};
use crucible_qemu::native_node_control::owned_operation::{
    InitialEvidenceBudget, InitialEvidenceStore, OriginalOperationEndpoint,
    OriginalPreparationDriver, OriginalPreparationProgress,
};

struct Endpoint {
    channel: NativeChannel,
    preparation: NativePrefixPreparation,
}

impl OriginalOperationEndpoint for Endpoint {
    fn prefix_preparation(&self) -> Option<&NativePrefixPreparation> {
        Some(&self.preparation)
    }

    fn send_original(&self, frame: &NativeFrame) -> Result<bool, ArchiveError> {
        self.channel.send(frame).map_err(|_| ArchiveError::Conflict)
    }

    fn receive_original(&self) -> Result<Option<NativeFrame>, ArchiveError> {
        self.channel.receive().map_err(|_| ArchiveError::Conflict)
    }
}

fn initialization(preparation: &NativePrefixPreparation) -> NativeInitializationReceipt {
    let original = &preparation
        .original_effect
        .original_root
        .administration
        .phase
        .initialization;
    NativeInitializationReceipt {
        status: NativeInitializationStatus::Applied,
        applied_callbacks: 3,
        sequence: U64::new(1),
        hold_generation: U64::new(1),
        prepared_scope_hash: original.preparation.scope.identity_digest().unwrap(),
        initialization_commitment: original.identity_digest().unwrap(),
        original_cut_digest: [19; 32],
        realize_request_digest: original.realize_request_digest,
    }
}

fn modeled_facts(preparation: &NativePrefixPreparation) -> NativePrefixPreparationFacts {
    let observation = NativePrefixPreparationObservation {
        preparation: preparation.clone(),
        initialization: initialization(preparation),
        initial: position(0, Phase::BoundaryControl),
        epoch_incarnation: U64::new(1),
        cpu_incarnation: U64::new(26),
        next_cpu_deadline_ps: U64::new(50),
        first_timer: None,
    };
    NativePrefixPreparationFacts::decode(&observation.encode().unwrap()).unwrap()
}

fn retain(
    path: &std::path::Path,
) -> (
    OriginalPreparationDriver<Endpoint>,
    NativeChannel,
    NativePrefixPreparationFacts,
) {
    let (preparation, _) = prefix_original();
    let facts = modeled_facts(&preparation);
    let store = InitialEvidenceStore::create(
        path,
        preparation.clone(),
        initialization(&preparation),
        InitialEvidenceBudget {
            lifetime_bytes: 65_536,
        },
    )
    .unwrap();
    let (channel, peer) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::PrefixEffect).unwrap();
    (
        OriginalPreparationDriver::retain(
            Endpoint {
                channel,
                preparation,
            },
            store,
        ),
        peer,
        facts,
    )
}

#[test]
fn initial_query_and_offered_ack_cannot_settle_before_consumed_response() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original.initial");
    let (mut driver, peer, facts) = retain(&path);
    let before = std::fs::read(&path).unwrap();
    assert!(!driver.settled());
    assert_eq!(driver.poll().unwrap(), OriginalPreparationProgress::Pending);
    assert!(matches!(
        peer.receive().unwrap(),
        Some(NativeFrame::QueryPrefixPreparation { .. })
    ));
    assert_eq!(peer.receive().unwrap(), None);

    assert!(
        peer.send(&NativeFrame::PrefixPreparationFacts(Box::new(
            facts.clone()
        )))
        .unwrap()
    );
    assert_eq!(
        driver.poll().unwrap(),
        OriginalPreparationProgress::FactsRetained
    );
    assert!(std::fs::read(&path).unwrap().len() > before.len());
    assert!(!driver.settled());
    assert!(driver.consumed_acknowledgement().is_none());
    assert_eq!(driver.poll().unwrap(), OriginalPreparationProgress::Pending);
    let Some(NativeFrame::AcknowledgePrefixPreparation(offered)) = peer.receive().unwrap() else {
        panic!("initial facts must expose only the original preparation ACK");
    };
    assert!(!driver.settled());

    assert!(
        peer.send(&NativeFrame::PrefixPreparationAcknowledged(offered.clone()))
            .unwrap()
    );
    assert_eq!(
        driver.poll().unwrap(),
        OriginalPreparationProgress::AcknowledgementConsumed
    );
    assert!(driver.settled());
    assert_eq!(driver.facts(), Some(&facts));
    assert_eq!(driver.consumed_acknowledgement(), Some(&offered));
    assert_eq!(peer.receive().unwrap(), None);
    let durable = std::fs::read(&path).unwrap();
    assert!(
        durable
            .windows(640)
            .any(|bytes| bytes == facts.canonical_bytes())
    );
    assert!(
        InitialEvidenceStore::create(
            &path,
            prefix_original().0.clone(),
            initialization(&prefix_original().0),
            InitialEvidenceBudget {
                lifetime_bytes: 65_536
            }
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), durable);
}

#[test]
fn foreign_consumed_ack_fences_the_same_initial_journal_without_compute() {
    let directory = tempfile::tempdir().unwrap();
    let (mut driver, peer, facts) = retain(&directory.path().join("original.initial"));
    driver.poll().unwrap();
    peer.receive().unwrap();
    peer.send(&NativeFrame::PrefixPreparationFacts(Box::new(facts)))
        .unwrap();
    driver.poll().unwrap();
    driver.poll().unwrap();
    let Some(NativeFrame::AcknowledgePrefixPreparation(mut offered)) = peer.receive().unwrap()
    else {
        panic!("missing offered ACK");
    };
    offered.epoch_incarnation = U64::new(2);
    peer.send(&NativeFrame::PrefixPreparationAcknowledged(offered))
        .unwrap();

    assert!(driver.poll().is_err());
    assert!(driver.failure().is_some());
    assert!(!driver.settled());
    assert!(driver.consumed_acknowledgement().is_none());
    assert!(driver.poll().is_err());
    assert_eq!(peer.receive().unwrap(), None);
}

#[test]
fn invalid_initial_receipt_or_insufficient_budget_creates_no_file() {
    let directory = tempfile::tempdir().unwrap();
    let (preparation, _) = prefix_original();
    let path = directory.path().join("original.initial");
    let mut foreign = initialization(&preparation);
    foreign.initialization_commitment[0] ^= 1;
    assert!(
        InitialEvidenceStore::create(
            &path,
            preparation.clone(),
            foreign,
            InitialEvidenceBudget {
                lifetime_bytes: 65_536
            }
        )
        .is_err()
    );
    assert!(!path.exists());
    assert!(
        InitialEvidenceStore::create(
            &path,
            preparation.clone(),
            initialization(&preparation),
            InitialEvidenceBudget { lifetime_bytes: 1 }
        )
        .is_err()
    );
    assert!(!path.exists());
}

#[test]
fn unobserved_endpoint_preserves_actual_child_and_vacant_archive_before_compute() {
    use crucible_qemu::native_node_control::owned_operation::{
        NativeOwnedPrefixRefusal, NativeOwnedPrefixSession,
    };
    use std::process::Command;
    use std::time::Duration;

    // This exec child has no QEMU/source authority. It tests the unique actual
    // wait owner and refusal before Compute, under the existing five-second reap.
    if std::env::var_os("CRUCIBLE_INITIAL_SESSION_REFUSAL_CHILD").is_some() {
        std::thread::park_timeout(Duration::from_secs(30));
        return;
    }
    let (mut endpoint, peer, actual_preparation, original) = unobserved_endpoint();
    let directory = tempfile::tempdir().unwrap();
    let initial = InitialEvidenceStore::create(
        directory.path().join("original.initial"),
        actual_preparation.clone(),
        initialization(&actual_preparation),
        InitialEvidenceBudget {
            lifetime_bytes: 65_536,
        },
    )
    .unwrap();
    let path = directory.path().join("command.archive");
    let archive = Archive::create(
        &path,
        original.command.scope.identity_digest().unwrap(),
        actual_preparation.identity_digest().unwrap(),
        ArchiveBudget {
            lifetime_bytes: 65_672,
            lifetime_commands: 1,
            maximum_prefixes: 2,
        },
    )
    .unwrap();
    let before = std::fs::read(&path).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "initial_session::unobserved_endpoint_preserves_actual_child_and_vacant_archive_before_compute", "--nocapture"])
        .env("CRUCIBLE_INITIAL_SESSION_REFUSAL_CHILD", "1")
        .spawn().unwrap();
    let process_id = child.id();
    endpoint.bind_process(process_id).unwrap();
    let mut session = NativeOwnedPrefixSession::retain(child, endpoint, archive, initial);
    assert_eq!(session.process_id(), process_id);
    assert!(matches!(
        session.supervision_refusal(),
        Some(NativeOwnedPrefixRefusal::ProcessBinding)
    ));
    assert!(session.poll().is_err());
    let mut failure = match session.into_operation(original) {
        Ok(_) => panic!("unobserved endpoint must not reserve Compute"),
        Err(failure) => failure,
    };
    assert_eq!(failure.session().unwrap().process_id(), process_id);
    assert_eq!(
        failure.session().unwrap().archive_state(),
        TurnoverState::Vacant
    );
    assert!(failure.operation().is_none());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(peer.receive().unwrap(), None);

    failure.dispose(Duration::from_secs(5)).unwrap();
    assert!(failure.session().unwrap().reaped());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

fn unobserved_endpoint() -> (
    crucible_qemu::native_node_control::NativeAdministrationTransport,
    NativeChannel,
    NativePrefixPreparation,
    NativeEffectCompute,
) {
    use crucible_qemu::native_node_control::{
        NativeAdministrationTransport, NativeFixedMicrovmParameters, NativePrefixParameters,
    };
    let (prepared, original) = prefix_original();
    let root = &prepared.original_effect.original_root;
    let (endpoint, launch) = NativeAdministrationTransport::prepare_prefix(
        root.administration.phase.clone(),
        root.administration.policy_digest,
        9,
        NativeFixedMicrovmParameters {
            policy_digest: root.policy_digest,
            firmware_sha256: root.firmware_sha256,
            firmware_length: root.firmware_length,
            ram_length: root.ram_length,
            seed: root.seed,
            maximum_service_span: root.maximum_service_span,
            mapping: root.mapping,
            maximum_callbacks: root.maximum_callbacks,
        },
        NativePrefixParameters {
            effect_policy_digest: prepared.original_effect.policy_digest,
            maximum_callbacks: prepared.original_effect.maximum_callbacks,
            maximum_service_span: prepared.original_effect.maximum_service_span,
            prefix_policy_digest: prepared.policy_digest,
            maximum_prefixes: prepared.maximum_prefixes,
        },
    )
    .unwrap();
    let peer = NativeChannel::from_prepared_socket_for_edition(
        launch.into_socket(),
        NativeControlEdition::PrefixEffect,
    )
    .unwrap();
    assert!(matches!(
        peer.receive().unwrap(),
        Some(NativeFrame::PreparePrefix(_))
    ));
    let actual_preparation = endpoint.prefix_preparation().unwrap().clone();
    (endpoint, peer, actual_preparation, original)
}

#[test]
fn initial_file_collision_returns_actual_child_and_all_original_owners() {
    use crucible_qemu::native_node_control::owned_operation::NativeOwnedPrefixSession;
    use std::process::Command;
    use std::time::Duration;

    if std::env::var_os("CRUCIBLE_INITIAL_SESSION_CREATION_CHILD").is_some() {
        std::thread::park_timeout(Duration::from_secs(30));
        return;
    }
    let (endpoint, peer, preparation, original) = unobserved_endpoint();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("initial.already-retained");
    let existing = b"uncertain original bytes must remain unchanged";
    std::fs::write(&path, existing).unwrap();
    let command_path = directory.path().join("command.archive");
    let archive = Archive::create(
        &command_path,
        original.command.scope.identity_digest().unwrap(),
        preparation.identity_digest().unwrap(),
        ArchiveBudget {
            lifetime_bytes: 65_672,
            lifetime_commands: 1,
            maximum_prefixes: 2,
        },
    )
    .unwrap();
    let command_bytes = std::fs::read(&command_path).unwrap();
    let receipt = initialization(&preparation);
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "initial_session::initial_file_collision_returns_actual_child_and_all_original_owners",
            "--nocapture",
        ])
        .env("CRUCIBLE_INITIAL_SESSION_CREATION_CHILD", "1")
        .spawn()
        .unwrap();
    let process_id = child.id();
    let mut failure = match NativeOwnedPrefixSession::create(
        child,
        endpoint,
        archive,
        &path,
        receipt.clone(),
        InitialEvidenceBudget {
            lifetime_bytes: 65_536,
        },
    ) {
        Ok(_) => panic!("an existing original file cannot become a live session"),
        Err(failure) => failure,
    };
    assert_eq!(failure.process_id(), process_id);
    assert!(!failure.reaped());
    assert_eq!(failure.path(), path);
    assert_eq!(failure.initialization(), &receipt);
    assert_eq!(failure.preparation(), Some(&preparation));
    assert!(matches!(failure.error(), Some(ArchiveError::Io(_))));
    assert_eq!(failure.archive_state(), TurnoverState::Vacant);
    assert_eq!(std::fs::read(&path).unwrap(), existing);
    assert_eq!(std::fs::read(&command_path).unwrap(), command_bytes);
    assert_eq!(peer.receive().unwrap(), None);

    failure.dispose(Duration::from_secs(5)).unwrap();
    assert!(failure.reaped());
    assert_eq!(std::fs::read(&path).unwrap(), existing);
    assert_eq!(std::fs::read(&command_path).unwrap(), command_bytes);
}

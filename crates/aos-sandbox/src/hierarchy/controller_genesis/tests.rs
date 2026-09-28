//! Actual protected completion rows, not installed Controller/Root authority.
//!
//! The tests use the same canonical Source planner and internal owner reducers
//! as production. They cannot construct a live Root proof or bypass fixed
//! Controller issuer custody; they exercise the final durable-row join only.

use std::fs;
use std::os::unix::fs::MetadataExt as _;

use aos_sandbox_core::ProjectId;

use super::*;
use crate::JournalLimits;
use crate::hierarchy::source_genesis::tests as source_fixture;

struct Fixture {
    controller_directory: tempfile::TempDir,
    source_directory: tempfile::TempDir,
    controller: Journal,
    source: Journal,
    acceptance: ControllerSourceGenesisAcceptanceRecordV1,
    receipt: SourceTreeGenesisReceiptV1,
    floor_ack: [u8; 144],
}

impl Fixture {
    fn new() -> Self {
        let controller_directory = source_fixture::directory();
        let source_directory = source_fixture::directory();
        let mut controller = open_controller(controller_directory.path());
        let mut source = source_fixture::open(source_directory.path(), JournalLimits::default());
        let receipt = source_fixture::append(&mut source);
        let acceptance = source_fixture::acceptance(receipt.project());
        assert_eq!(receipt.acceptance_digest(), acceptance.digest());

        controller
            .commit_controller_source_genesis_transition(
                &records::acceptance_transaction(&acceptance).unwrap(),
                Transition::Accept,
            )
            .unwrap();
        let floor_ack = records::ack_bytes(
            acceptance.digest(),
            source_fixture::ack(&receipt).root_floor,
            receipt.digest(),
        )
        .unwrap();
        controller
            .commit_controller_source_genesis_transition(
                &records::ack_transaction(receipt.project(), &floor_ack).unwrap(),
                Transition::FloorAck,
            )
            .unwrap();
        source_fixture::anchor_with_controller_floor(
            &mut source,
            &receipt,
            records::ack_digest(&floor_ack),
        );
        Self {
            controller_directory,
            source_directory,
            controller,
            source,
            acceptance,
            receipt,
            floor_ack,
        }
    }

    fn source_ack(&self) -> crate::journal::source_tree_genesis::SourceGenesisAckV1 {
        let rows = self.source.source_tree_genesis_rows_v1().unwrap();
        assert!(rows.pending.is_none());
        assert_eq!(
            rows.receipts.get(&self.receipt.project()),
            Some(&self.receipt)
        );
        rows.acks.get(&self.receipt.project()).unwrap().clone()
    }

    fn require_completion(&self) -> Result<(), SourceGenesisErrorV1> {
        let ack = self.source_ack();
        assert_eq!(ack.controller_floor, records::ack_digest(&self.floor_ack));
        require_completed_source_ack(
            &self.controller,
            &self.acceptance,
            &self.receipt,
            ack.root_floor,
            ack.digest(),
        )
    }

    fn complete(&mut self, source_ack: ObjectDigest) {
        let complete =
            records::complete_bytes(&self.floor_ack, source_ack, self.source_ack().root_floor)
                .unwrap();
        self.controller
            .commit_controller_source_genesis_transition(
                &records::complete_transaction(self.receipt.project(), &complete).unwrap(),
                Transition::Complete,
            )
            .unwrap();
    }

    fn reopen(self) -> Self {
        let Self {
            controller_directory,
            source_directory,
            controller,
            source,
            acceptance,
            receipt,
            floor_ack,
        } = self;
        drop(controller);
        drop(source);
        let controller = open_controller(controller_directory.path());
        let source = source_fixture::open(source_directory.path(), JournalLimits::default());
        Self {
            controller_directory,
            source_directory,
            controller,
            source,
            acceptance,
            receipt,
            floor_ack,
        }
    }
}

fn open_controller(directory: &Path) -> Journal {
    Journal::open_protected_at_uid(
        directory,
        CONTROLLER_JOURNAL,
        JournalLimits::default(),
        fs::metadata(directory).unwrap().uid(),
    )
    .unwrap()
    .0
}

#[test]
fn source_ack_before_controller_complete_remains_incomplete_across_reopen() {
    let fixture = Fixture::new();
    let sequence = fixture.controller.snapshot_sequence();
    assert!(fixture.require_completion().is_err());
    assert_eq!(fixture.controller.snapshot_sequence(), sequence);
    assert!(records::pending(&fixture.controller).unwrap().is_some());

    let mut fixture = fixture.reopen();
    assert!(fixture.require_completion().is_err());
    fixture.complete(fixture.source_ack().digest());
    let sequence = fixture.controller.snapshot_sequence();
    fixture.require_completion().unwrap();
    assert_eq!(fixture.controller.snapshot_sequence(), sequence);
    assert!(records::pending(&fixture.controller).unwrap().is_none());

    let fixture = fixture.reopen();
    fixture.require_completion().unwrap();
    assert_eq!(fixture.controller.snapshot_sequence(), sequence);
}

#[test]
fn controller_completion_rejects_foreign_source_ack_floor_and_acceptance() {
    let mut fixture = Fixture::new();
    fixture.complete(fixture.source_ack().digest());
    let sequence = fixture.controller.snapshot_sequence();
    let ack = fixture.source_ack();
    for (acceptance, floor, source_ack) in [
        (
            fixture.acceptance.clone(),
            ack.root_floor,
            ObjectDigest::from_bytes([71; 32]),
        ),
        (
            fixture.acceptance.clone(),
            ObjectDigest::from_bytes([72; 32]),
            ack.digest(),
        ),
        (
            source_fixture::acceptance(ProjectId::from_bytes([73; 16])),
            ack.root_floor,
            ack.digest(),
        ),
    ] {
        assert!(
            require_completed_source_ack(
                &fixture.controller,
                &acceptance,
                &fixture.receipt,
                floor,
                source_ack,
            )
            .is_err()
        );
    }
    assert_eq!(fixture.controller.snapshot_sequence(), sequence);
    fixture.require_completion().unwrap();
}

#[test]
fn canonical_but_foreign_controller_complete_never_confirms_actual_source_ack() {
    let mut fixture = Fixture::new();
    // The structural reducer can validate framing, but only the held consumer
    // can join the actual Source cut. This deliberately wrong internal write
    // must not become a final owner-derived readback after cold replay.
    fixture.complete(ObjectDigest::from_bytes([74; 32]));
    let sequence = fixture.controller.snapshot_sequence();
    assert!(fixture.require_completion().is_err());
    assert_eq!(fixture.controller.snapshot_sequence(), sequence);
    let fixture = fixture.reopen();
    assert!(fixture.require_completion().is_err());
    assert_eq!(fixture.controller.snapshot_sequence(), sequence);
}

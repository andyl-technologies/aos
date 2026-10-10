//! Actual file durability, finite turnover and preserved original-history controls.
//!
//! Native retirement bodies are explicitly modeled here. These tests qualify
//! storage and correlation, not a native retirement issuer or release authority.

// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::Write;

use crucible_node_contract::{HashRef, Id, Phase, Position, U64};
use crucible_protocol::node_control::{
    BoundaryPolicy, ExecutionCommand, ExecutionKind, NativeEffectCompute, NativeEffectProgress,
    NativeEffectProgressStatus, NativePrefixAcknowledgement, OwnerScope,
};
use crucible_qemu::native_node_control::owned_operation::{
    Archive, ArchiveBudget, ArchiveError, PrefixEvidence, TerminalEvidence, TurnoverState,
};

// crucible-lint: allow rust-allow -- This test-only module panics when original-custody assertions fail.
// crucible-lint: allow panic-shortcut -- Test setup and assertion failures are intentional test failures.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod controls {
    use super::*;

    pub(super) fn position(time: u64, phase: Phase) -> Position {
        Position {
            time_ps: U64::new(time),
            microstep: U64::new(0),
            phase,
        }
    }

    fn command(sequence: u64) -> NativeEffectCompute {
        let id = |text: &str| Id::new(text).unwrap();
        let hash = |domain: &str| HashRef {
            algorithm: "blake3-256".into(),
            domain: domain.into(),
            digest: "01".repeat(32),
        };
        let mut command = ExecutionCommand {
            sequence: U64::new(sequence),
            scope: OwnerScope {
                session: id("session/a"),
                incarnation: id("incarnation/a"),
                activation: id("activation/1"),
                node: id("machine/a"),
                owner: id("owner/a"),
                world_generation: U64::new(1),
                owner_generation: U64::new(3),
                world_binding: hash("cnp.world-binding.v1"),
                owner_binding: hash("cnp.owner-binding.v1"),
            },
            operation: id("operation/1"),
            grant: id("grant/1"),
            input_epoch: id("input/epoch"),
            input_batch: id("batch/1"),
            input_batch_hash: hash("cnp.input-batch.v1"),
            closed_input_prefix: position(100, Phase::BoundaryControl),
            authorization_digest: [7; 32],
            kind: ExecutionKind::ExactRun {
                start: position(0, Phase::BoundaryControl),
                limit: position(100, Phase::BoundaryControl),
                boundary_policy: BoundaryPolicy::HorizonPark,
            },
        };
        command.input_batch_hash = crucible_node_contract::InputBatch {
            schema_version: 1,
            execution_owner_id: command.scope.owner.clone(),
            input_epoch: command.input_epoch.clone(),
            batch_id: command.input_batch.clone(),
            batch_sequence: U64::new(1),
            events: Vec::new(),
            extensions: Default::default(),
        }
        .identity()
        .unwrap();
        NativeEffectCompute {
            command,
            effect_preparation: [9; 32],
            maximum_callbacks: 2,
            maximum_service_span: U64::new(1),
            input_batch_sequence: U64::new(1),
        }
    }

    fn terminal(original: &NativeEffectCompute) -> TerminalEvidence {
        let result = NativeEffectProgress {
            scope: original.command.scope.identity_digest().unwrap(),
            effect_preparation: original.effect_preparation,
            grant_digest: original.command.authorization_digest,
            command_digest: original.command.identity_digest().unwrap(),
            sequence: original.command.sequence,
            cut_id: U64::new(1),
            raw_before: U64::new(0),
            raw_after: U64::new(1),
            evaluated: position(50, Phase::Reaction),
            evaluation_id: U64::new(1),
            evaluation_generation: U64::new(26),
            resulting: position(100, Phase::BoundaryControl),
            returned_service_count: U64::new(1),
            status: NativeEffectProgressStatus::Completed,
            end_result: 0,
        };
        let ack = NativePrefixAcknowledgement::from_initial(&result)
            .unwrap()
            .encode()
            .unwrap();
        TerminalEvidence {
            prefixes: vec![PrefixEvidence {
                result: result.encode().unwrap(),
                offered_acknowledgement: ack.clone(),
                consumed_acknowledgement: ack,
            }],
            native_proposal: b"modeled-original-native-terminal-proposal".to_vec(),
        }
    }

    fn budget(commands: u64) -> ArchiveBudget {
        ArchiveBudget {
            lifetime_bytes: commands * 65_536 + 136,
            lifetime_commands: commands,
            maximum_prefixes: 2,
        }
    }

    pub(super) fn prefix_original() -> (
        crucible_protocol::node_control::NativePrefixPreparation,
        NativeEffectCompute,
    ) {
        use crucible_protocol::node_control::{
            NativeAdministrativePreparation, NativeEffectPreparation, NativeFixedMicrovmMapping,
            NativeFixedMicrovmPreparation, NativeInitializationPreparation, NativePhaseMapping,
            NativePhasePreparation, NativePrefixPreparation, NativePreparation,
        };
        let mut original = command(1);
        let initialization = NativeInitializationPreparation {
            preparation: NativePreparation {
                scope: original.command.scope.clone(),
                boundary: position(0, Phase::BoundaryControl),
                maximum_commands: U64::new(8),
            },
            realize_operation: Id::new("operation/realize").unwrap(),
            realize_request_digest: [11; 32],
            policy_digest: [12; 32],
            class_mask: 7,
            maximum_callbacks: 64,
        };
        let phase = NativePhasePreparation {
            initialization,
            policy_digest: [13; 32],
            mapping: NativePhaseMapping::InstructionReaction,
            maximum_microstep: U64::new(1024),
        };
        let administration = NativeAdministrativePreparation {
            phase,
            policy_digest: [14; 32],
            descriptor_slot: 9,
            socket_device: 1,
            socket_inode: 2,
        };
        let root = NativeFixedMicrovmPreparation {
            administration,
            policy_digest: [15; 32],
            firmware_sha256: [16; 32],
            firmware_length: U64::new(65_536),
            ram_length: U64::new(32 * 1024 * 1024),
            seed: U64::new(8254),
            maximum_microstep: U64::new(1024),
            maximum_service_span: U64::new(64),
            mapping: NativeFixedMicrovmMapping::InstructionThenTimers,
            maximum_callbacks: 64,
        };
        let preparation = NativePrefixPreparation {
            original_effect: NativeEffectPreparation {
                original_root: root,
                policy_digest: [17; 32],
                maximum_callbacks: 2,
                maximum_service_span: U64::new(4),
            },
            policy_digest: [18; 32],
            maximum_prefixes: 2,
        };
        original.effect_preparation = preparation.identity_digest().unwrap();
        original.maximum_service_span = U64::new(4);
        original.command.closed_input_prefix = position(350, Phase::BoundaryControl);
        original.command.kind = ExecutionKind::ExactRun {
            start: position(0, Phase::BoundaryControl),
            limit: position(350, Phase::BoundaryControl),
            boundary_policy: BoundaryPolicy::HorizonPark,
        };
        (preparation, original)
    }

    fn create(path: &std::path::Path, original: &NativeEffectCompute, count: u64) -> Archive {
        Archive::create(
            path,
            original.command.scope.identity_digest().unwrap(),
            original.effect_preparation,
            budget(count),
        )
        .unwrap()
    }

    fn restore(path: &std::path::Path, original: &NativeEffectCompute, count: u64) -> Archive {
        Archive::restore(
            path,
            original.command.scope.identity_digest().unwrap(),
            original.effect_preparation,
            budget(count),
        )
        .unwrap()
    }

    #[test]
    fn reservation_survives_restore_and_fences_the_next_original() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original.archive");
        let original = command(1);
        let mut archive = create(&path, &original, 2);
        archive.reserve(&original).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        archive.reserve(&original).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(matches!(
            archive.reserve(&command(2)),
            Err(ArchiveError::Conflict)
        ));
        drop(archive);

        let mut restored = restore(&path, &original, 2);
        assert_eq!(
            restored.state(),
            TurnoverState::CommandReserved { sequence: 1 }
        );
        assert!(restored.pending_original().is_some());
        assert!(matches!(
            restored.reserve(&command(2)),
            Err(ArchiveError::Conflict)
        ));
    }

    #[test]
    fn terminal_archive_restores_without_claiming_native_retirement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original.archive");
        let original = command(1);
        let evidence = terminal(&original);
        let mut archive = create(&path, &original, 2);
        archive.reserve(&original).unwrap();
        let digest = archive.archive_terminal(&evidence).unwrap();
        let exact = std::fs::read(&path).unwrap();
        assert_eq!(archive.archive_terminal(&evidence).unwrap(), digest);
        assert_eq!(std::fs::read(&path).unwrap(), exact);
        drop(archive);

        let mut restored = restore(&path, &original, 2);
        assert_eq!(
            restored.state(),
            TurnoverState::TerminalArchived {
                sequence: 1,
                terminal_digest: digest
            }
        );
        assert_eq!(
            restored.pending_original().unwrap().terminal,
            Some(evidence)
        );
        assert!(matches!(
            restored.reserve(&command(2)),
            Err(ArchiveError::Conflict)
        ));
        assert!(matches!(
            restored.record_native_receipt([3; 32], b"foreign"),
            Err(ArchiveError::Conflict)
        ));
    }

    #[test]
    fn receipt_turnover_preserves_history_and_refuses_old_command_replay() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original.archive");
        let original = command(1);
        let evidence = terminal(&original);
        let mut archive = create(&path, &original, 2);
        archive.reserve(&original).unwrap();
        let terminal_digest = archive.archive_terminal(&evidence).unwrap();
        archive
            .record_native_receipt(terminal_digest, b"modeled-native-retirement-receipt")
            .unwrap();
        let TurnoverState::ReceiptStored { receipt_digest, .. } = archive.state() else {
            panic!("original receipt was not retained");
        };
        assert!(matches!(
            archive.reserve(&command(2)),
            Err(ArchiveError::Conflict)
        ));
        archive
            .record_native_commit(receipt_digest, b"modeled-native-retirement-commit")
            .unwrap();
        assert!(matches!(
            archive.state(),
            TurnoverState::RetirementCommitted { sequence: 1, .. }
        ));
        assert!(matches!(
            archive.reserve(&original),
            Err(ArchiveError::Conflict)
        ));
        let history = archive.historical(1).unwrap();
        assert_eq!(history.terminal, Some(evidence));
        assert_eq!(
            history.native_receipt,
            Some(b"modeled-native-retirement-receipt".to_vec())
        );
        drop(archive);

        let mut restored = restore(&path, &original, 2);
        assert_eq!(restored.historical(1).unwrap(), history);
        assert!(matches!(
            restored.reserve(&original),
            Err(ArchiveError::Conflict)
        ));
        restored.reserve(&command(2)).unwrap();
        assert_eq!(
            restored.state(),
            TurnoverState::CommandReserved { sequence: 2 }
        );
    }

    #[test]
    fn lifetime_budget_exhaustion_retains_every_tombstone() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original.archive");
        let original = command(1);
        let mut archive = create(&path, &original, 1);
        archive.reserve(&original).unwrap();
        let digest = archive.archive_terminal(&terminal(&original)).unwrap();
        archive
            .record_native_receipt(digest, b"modeled-native-receipt")
            .unwrap();
        let TurnoverState::ReceiptStored { receipt_digest, .. } = archive.state() else {
            panic!("original receipt was not retained");
        };
        archive
            .record_native_commit(receipt_digest, b"modeled-native-retirement-commit")
            .unwrap();
        let exact = std::fs::read(&path).unwrap();
        assert!(matches!(
            archive.reserve(&command(2)),
            Err(ArchiveError::Budget)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), exact);
        assert!(archive.historical(1).unwrap().native_receipt.is_some());
    }

    #[test]
    fn changed_consumed_ack_and_nonterminal_effects_do_not_archive() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original.archive");
        let original = command(1);
        let mut archive = create(&path, &original, 1);
        archive.reserve(&original).unwrap();
        let exact = std::fs::read(&path).unwrap();
        let mut evidence = terminal(&original);
        evidence.prefixes[0].consumed_acknowledgement[191] ^= 1;
        assert!(archive.archive_terminal(&evidence).is_err());
        let mut evidence = terminal(&original);
        let mut result = NativeEffectProgress::decode(&evidence.prefixes[0].result).unwrap();
        result.status = NativeEffectProgressStatus::EffectsUnknown;
        evidence.prefixes[0].result = result.encode().unwrap();
        let ack = NativePrefixAcknowledgement::from_initial(&result)
            .unwrap()
            .encode()
            .unwrap();
        evidence.prefixes[0].offered_acknowledgement = ack.clone();
        evidence.prefixes[0].consumed_acknowledgement = ack;
        assert!(archive.archive_terminal(&evidence).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), exact);
    }

    #[test]
    fn durable_receipt_restore_keeps_the_native_commit_fence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original.archive");
        let original = command(1);
        let mut archive = create(&path, &original, 2);
        archive.reserve(&original).unwrap();
        let terminal_digest = archive.archive_terminal(&terminal(&original)).unwrap();
        archive
            .record_native_receipt(terminal_digest, b"modeled-original-native-receipt")
            .unwrap();
        let exact = std::fs::read(&path).unwrap();
        archive
            .record_native_receipt(terminal_digest, b"modeled-original-native-receipt")
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), exact);
        let state = archive.state();
        drop(archive);

        let mut restored = restore(&path, &original, 2);
        assert_eq!(restored.state(), state);
        assert!(matches!(
            restored.reserve(&command(2)),
            Err(ArchiveError::Conflict)
        ));
        assert!(matches!(
            restored.record_native_commit([7; 32], b"foreign-confirmation"),
            Err(ArchiveError::Conflict)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), exact);
        let TurnoverState::ReceiptStored { receipt_digest, .. } = restored.state() else {
            panic!("restored original receipt was not retained");
        };
        restored
            .record_native_commit(receipt_digest, b"modeled-native-retirement-commit")
            .unwrap();
        assert_eq!(
            restored.historical(1).unwrap().native_commit,
            Some(b"modeled-native-retirement-commit".to_vec())
        );
    }

    #[test]
    fn torn_tail_is_preserved_and_restore_remains_fenced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original.archive");
        let original = command(1);
        let mut archive = create(&path, &original, 1);
        archive.reserve(&original).unwrap();
        drop(archive);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0, 0, 0, 2, 0])
            .unwrap();
        let exact = std::fs::read(&path).unwrap();
        assert!(matches!(
            Archive::restore(
                &path,
                original.command.scope.identity_digest().unwrap(),
                original.effect_preparation,
                budget(1)
            ),
            Err(ArchiveError::Corrupt)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), exact);
    }

    #[test]
    fn actual_file_lock_refuses_a_concurrent_restored_owner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("original.archive");
        let original = command(1);
        let archive = create(&path, &original, 1);
        assert!(
            Archive::restore(
                &path,
                original.command.scope.identity_digest().unwrap(),
                original.effect_preparation,
                budget(1)
            )
            .is_err()
        );
        drop(archive);
        assert_eq!(restore(&path, &original, 1).state(), TurnoverState::Vacant);
    }

    #[test]
    fn restored_archive_retains_all_owners_without_native_recovery() {
        use std::cell::Cell;
        use std::rc::Rc;

        use crucible_protocol::node_control::{NativeFrame, NativePrefixPreparation};
        use crucible_qemu::native_node_control::owned_operation::{
            OriginalOperationDriver, OriginalOperationEndpoint,
        };

        struct Endpoint {
            preparation: NativePrefixPreparation,
            sends: Rc<Cell<usize>>,
        }

        impl OriginalOperationEndpoint for Endpoint {
            fn prefix_preparation(&self) -> Option<&NativePrefixPreparation> {
                Some(&self.preparation)
            }

            fn send_original(&self, _: &NativeFrame) -> Result<bool, ArchiveError> {
                self.sends.set(self.sends.get() + 1);
                Ok(true)
            }

            fn receive_original(&self) -> Result<Option<NativeFrame>, ArchiveError> {
                panic!("refused restored custody must not receive another frame");
            }
        }

        // Retirement bodies are modeled storage records, never native authority.
        for stage in 0..4 {
            let (preparation, original) = prefix_original();
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("retained.archive");
            let mut archive = create(&path, &original, 2);
            archive.reserve(&original).unwrap();
            if stage > 0 {
                let mut evidence = terminal(&original);
                let mut result =
                    NativeEffectProgress::decode(&evidence.prefixes[0].result).unwrap();
                result.resulting = position(350, Phase::BoundaryControl);
                let acknowledgement = NativePrefixAcknowledgement::from_initial(&result)
                    .unwrap()
                    .encode()
                    .unwrap();
                evidence.prefixes[0] = PrefixEvidence {
                    result: result.encode().unwrap(),
                    offered_acknowledgement: acknowledgement.clone(),
                    consumed_acknowledgement: acknowledgement,
                };
                let terminal_digest = archive.archive_terminal(&evidence).unwrap();
                if stage > 1 {
                    archive
                        .record_native_receipt(terminal_digest, b"modeled-native-receipt")
                        .unwrap();
                }
                if stage > 2 {
                    let TurnoverState::ReceiptStored { receipt_digest, .. } = archive.state()
                    else {
                        panic!("modeled receipt was not retained");
                    };
                    archive
                        .record_native_commit(receipt_digest, b"modeled-native-commit")
                        .unwrap();
                }
            }
            let retained_state = archive.state();
            drop(archive);
            let restored = restore(&path, &original, 2);
            let retained_bytes = std::fs::read(&path).unwrap();
            let sends = Rc::new(Cell::new(0));
            let endpoint = Endpoint {
                preparation,
                sends: sends.clone(),
            };
            let mut offered = original.clone();
            if stage == 3 {
                offered.command.sequence = U64::new(2);
            }

            let mut driver = OriginalOperationDriver::retain(endpoint, restored, offered.clone());

            assert!(matches!(driver.failure(), Some(ArchiveError::Conflict)));
            assert!(driver.poll().is_err());
            assert_eq!(driver.original(), &offered);
            assert_eq!(driver.archive_state(), retained_state);
            assert_eq!(sends.get(), 0);
            assert_eq!(std::fs::read(&path).unwrap(), retained_bytes);
            assert!(driver.journal().is_none());
            assert!(driver.request_original_again().is_err());
            assert!(driver.request_continuation().is_err());
        }
    }

    #[test]
    fn foreign_archive_prefix_quota_retains_owners_before_exposure() {
        use std::cell::Cell;
        use std::rc::Rc;

        use crucible_protocol::node_control::{NativeFrame, NativePrefixPreparation};
        use crucible_qemu::native_node_control::owned_operation::{
            OriginalOperationDriver, OriginalOperationEndpoint,
        };

        struct Endpoint {
            preparation: NativePrefixPreparation,
            sends: Rc<Cell<usize>>,
        }
        impl OriginalOperationEndpoint for Endpoint {
            fn prefix_preparation(&self) -> Option<&NativePrefixPreparation> {
                Some(&self.preparation)
            }
            fn send_original(&self, _: &NativeFrame) -> Result<bool, ArchiveError> {
                self.sends.set(self.sends.get() + 1);
                Ok(true)
            }
            fn receive_original(&self) -> Result<Option<NativeFrame>, ArchiveError> {
                Ok(None)
            }
        }

        let (mut preparation, mut original) = prefix_original();
        preparation.maximum_prefixes = 3;
        original.effect_preparation = preparation.identity_digest().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("refused-quota.archive");
        let archive = create(&path, &original, 1);
        assert_eq!(archive.maximum_prefixes(), 2);
        let exact = std::fs::read(&path).unwrap();
        let sends = Rc::new(Cell::new(0));
        let endpoint = Endpoint {
            preparation,
            sends: sends.clone(),
        };
        let mut driver = OriginalOperationDriver::retain(endpoint, archive, original.clone());

        assert!(matches!(driver.failure(), Some(ArchiveError::Budget)));
        assert!(driver.poll().is_err());
        assert_eq!(driver.original(), &original);
        assert_eq!(driver.archive_state(), TurnoverState::Vacant);
        assert_eq!(sends.get(), 0);
        assert_eq!(std::fs::read(&path).unwrap(), exact);
        assert!(driver.request_continuation().is_err());
    }

    #[test]
    fn original_transport_reserves_durable_custody_and_fences_ack_echo() {
        use std::cell::Cell;
        use std::os::unix::net::UnixDatagram;

        use crucible_protocol::node_control::{
            NativeControlEdition, NativeFrame, NativePrefixPreparation, decode_frame_for_edition,
            encode_frame_for_edition,
        };
        use crucible_qemu::native_node_control::owned_operation::{
            OriginalOperationDriver, OriginalOperationEndpoint, OriginalOperationProgress,
        };

        // Actual sockets and file synchronization qualify host custody. The
        // supplied result remains explicitly modeled, without native handles.
        struct Endpoint {
            preparation: NativePrefixPreparation,
            socket: UnixDatagram,
            backpressure: Cell<bool>,
        }

        impl OriginalOperationEndpoint for Endpoint {
            fn prefix_preparation(&self) -> Option<&NativePrefixPreparation> {
                Some(&self.preparation)
            }

            fn send_original(&self, frame: &NativeFrame) -> Result<bool, ArchiveError> {
                if self.backpressure.replace(false) {
                    return Ok(false);
                }
                let bytes = encode_frame_for_edition(NativeControlEdition::PrefixEffect, frame)?;
                Ok(self.socket.send(&bytes)? == bytes.len())
            }

            fn receive_original(&self) -> Result<Option<NativeFrame>, ArchiveError> {
                let mut bytes = [0u8; 65_536];
                match self.socket.recv(&mut bytes) {
                    Ok(count) => Ok(Some(decode_frame_for_edition(
                        NativeControlEdition::PrefixEffect,
                        &bytes[..count],
                    )?)),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                    Err(error) => Err(error.into()),
                }
            }
        }

        let (preparation, original) = prefix_original();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("transport.archive");
        let archive = create(&path, &original, 1);
        let (socket, peer) = UnixDatagram::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let endpoint = Endpoint {
            preparation,
            socket,
            backpressure: Cell::new(true),
        };
        let mut driver = OriginalOperationDriver::retain(endpoint, archive, original.clone());

        assert_eq!(
            driver.archive_state(),
            TurnoverState::CommandReserved { sequence: 1 }
        );
        let reserved = std::fs::read(&path).unwrap();
        assert_eq!(driver.poll().unwrap(), OriginalOperationProgress::Pending);
        let mut packet = [0u8; 65_536];
        assert_eq!(
            peer.recv(&mut packet).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(std::fs::read(&path).unwrap(), reserved);
        assert_eq!(driver.poll().unwrap(), OriginalOperationProgress::Pending);
        let count = peer.recv(&mut packet).unwrap();
        assert_eq!(
            decode_frame_for_edition(NativeControlEdition::PrefixEffect, &packet[..count]).unwrap(),
            NativeFrame::EffectCompute(Box::new(original.clone()))
        );
        assert_eq!(driver.poll().unwrap(), OriginalOperationProgress::Pending);
        assert_eq!(
            peer.recv(&mut packet).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );

        let mut first =
            NativeEffectProgress::decode(&terminal(&original).prefixes[0].result).unwrap();
        first.status = NativeEffectProgressStatus::PartialPrefix;
        first.resulting = first.evaluated;
        peer.send(
            &encode_frame_for_edition(
                NativeControlEdition::PrefixEffect,
                &NativeFrame::EffectProgress(Box::new(first.clone())),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            driver.poll().unwrap(),
            OriginalOperationProgress::ResultRetained
        );
        assert!(driver.request_continuation().is_err());
        assert_eq!(driver.poll().unwrap(), OriginalOperationProgress::Pending);
        let count = peer.recv(&mut packet).unwrap();
        let offered =
            decode_frame_for_edition(NativeControlEdition::PrefixEffect, &packet[..count]).unwrap();
        assert!(matches!(offered, NativeFrame::AcknowledgePrefix(_)));

        let NativeFrame::AcknowledgePrefix(ack) = &offered else {
            panic!("expected the original offered ACK")
        };
        peer.send(
            &encode_frame_for_edition(
                NativeControlEdition::PrefixEffect,
                &NativeFrame::PrefixAcknowledged(ack.clone()),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            driver.poll().unwrap(),
            OriginalOperationProgress::AcknowledgementConsumed
        );
        driver.request_continuation().unwrap();
        assert_eq!(driver.poll().unwrap(), OriginalOperationProgress::Pending);
        let count = peer.recv(&mut packet).unwrap();
        let NativeFrame::ContinuePrefix(continuation) =
            decode_frame_for_edition(NativeControlEdition::PrefixEffect, &packet[..count]).unwrap()
        else {
            panic!("original continuation was not retained")
        };
        continuation.validate_initial(&first).unwrap();
        assert_eq!(&continuation.acknowledgement, ack);

        peer.send(
            &encode_frame_for_edition(
                NativeControlEdition::PrefixEffect,
                &NativeFrame::EffectProgress(Box::new(first)),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            driver.poll().unwrap(),
            OriginalOperationProgress::HistoricalRecovered
        );
        assert_eq!(driver.journal().unwrap().retained_prefixes(), 1);

        // Echoing the offered request never supplies native consumption. Failure
        // retains the original durable reservation and disables subsequent sends.
        peer.send(&encode_frame_for_edition(NativeControlEdition::PrefixEffect, &offered).unwrap())
            .unwrap();
        assert!(driver.poll().is_err());
        assert!(driver.failure().is_some());
        assert_eq!(driver.original(), &original);
        assert_eq!(driver.journal().unwrap().retained_prefixes(), 1);
        assert_eq!(
            driver.archive_state(),
            TurnoverState::CommandReserved { sequence: 1 }
        );
        assert!(driver.request_original_again().is_err());
        assert!(driver.poll().is_err());
        assert_eq!(
            peer.recv(&mut packet).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(std::fs::read(&path).unwrap(), reserved);
    }

    #[test]
    fn original_quantum_waits_for_consumed_ack_and_aggregates_without_new_budget() {
        use crucible_protocol::node_control::{
            NativeFrame, NativePrefixEvaluationKind, NativePrefixProgress,
        };
        use crucible_qemu::native_node_control::owned_operation::OriginalPrefixJournal;
        let (preparation, original) = prefix_original();
        let mut first =
            NativeEffectProgress::decode(&terminal(&original).prefixes[0].result).unwrap();
        first.status = NativeEffectProgressStatus::PartialPrefix;
        first.resulting = first.evaluated;
        let first_frame = NativeFrame::EffectProgress(Box::new(first.clone()));
        let mut journal = OriginalPrefixJournal::new(&preparation, original.clone()).unwrap();
        journal.observe_result(&first_frame).unwrap();
        journal.observe_result(&first_frame).unwrap();
        assert!(journal.continuation().is_err());
        let offered = journal.offer_acknowledgement().unwrap();
        assert!(journal.observe_acknowledgement(&offered).is_err());
        let NativeFrame::AcknowledgePrefix(ack) = offered else {
            panic!("missing original offered ACK")
        };
        journal
            .observe_acknowledgement(&NativeFrame::PrefixAcknowledged(ack))
            .unwrap();
        let continuation = journal.continuation().unwrap();
        assert_eq!(journal.continuation().unwrap(), continuation);

        let second = NativePrefixProgress {
            scope: first.scope,
            prefix_preparation: first.effect_preparation,
            grant_digest: first.grant_digest,
            command_digest: first.command_digest,
            sequence: first.sequence,
            cut_id: U64::new(2),
            previous_cut_id: first.cut_id,
            acknowledgement_sequence: U64::new(1),
            raw_before: U64::new(1),
            raw_after: U64::new(4),
            evaluated: position(100, Phase::Reaction),
            evaluation_kind: NativePrefixEvaluationKind::CpuService,
            parent_kind: None,
            evaluation_id: U64::new(1),
            evaluation_generation: U64::new(26),
            parent_id: U64::new(0),
            parent_generation: U64::new(0),
            resulting: position(350, Phase::BoundaryControl),
            cpu_retirements: U64::new(3),
            timer_callbacks: U64::new(0),
            cumulative_cpu_retirements: U64::new(4),
            cumulative_timer_callbacks: U64::new(0),
            status: NativeEffectProgressStatus::Completed,
            end_result: 0,
        };
        let mut foreign = second.clone();
        foreign.cumulative_cpu_retirements = U64::new(5);
        assert!(
            journal
                .observe_result(&NativeFrame::PrefixProgress(Box::new(foreign)))
                .is_err()
        );
        journal
            .observe_result(&NativeFrame::PrefixProgress(Box::new(second.clone())))
            .unwrap();
        journal.observe_result(&first_frame).unwrap();
        assert!(
            journal
                .terminal_evidence(b"modeled-native-proposal".to_vec())
                .is_err()
        );
        let NativeFrame::AcknowledgePrefix(ack) = journal.offer_acknowledgement().unwrap() else {
            panic!("missing final original ACK")
        };
        journal
            .observe_acknowledgement(&NativeFrame::PrefixAcknowledged(ack))
            .unwrap();

        let evidence = journal
            .terminal_evidence(b"modeled-native-proposal".to_vec())
            .unwrap();
        assert_eq!(evidence.prefixes.len(), 2);
        assert_eq!(evidence.prefixes[0].result, first.encode().unwrap());
        assert_eq!(evidence.prefixes[1].result, second.encode().unwrap());
        assert_eq!(journal.original(), &original);
        assert!(journal.continuation().is_err());
    }
}

// crucible-lint: allow rust-allow -- Real file/datagram custody controls intentionally panic on mismatch.
// crucible-lint: allow panic-shortcut -- Test-only fixture and assertion failures are deliberate failures.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "native_prefix_archive/initial_session.rs"]
mod initial_session;

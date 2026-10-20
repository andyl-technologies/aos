//! Binds a permanent Root response to an already completed transient purpose.
//!
//! ```text
//! AOSRPC02 | purpose:u64be (Delete=1, ExecutionNoApply=2, StopCleanup=3) | commitment[32]
//! ```
//!
//! These bytes carry comparison DATA. Their causal meaning requires the same
//! authenticated native connection and the private Root finisher that writes
//! them only after genuine transient financial disposition. EOF alone carries
//! no such meaning, including when the peer PIDFD still reports a live process.

use crate::host_execution_no_apply::closed_controller::ControllerCreateFailureAckDataV2;
use sha2::{Digest as _, Sha256};

/// Gives the exact permanent Root completion response width.
pub const ROOT_POLICY_POSITIVE_COMPLETION_BYTES_V2: usize = 48;

/// Derives the Delete response from the canonical final Source544 ACK digest.
///
/// The supplied digest is the existing canonical544 acknowledgement digest,
/// rather than a local endpoint archive head. This function grants no authority.
#[must_use]
pub fn delete_root_positive_completion_bytes_v2(
    acknowledgement: [u8; 32],
) -> [u8; ROOT_POLICY_POSITIVE_COMPLETION_BYTES_V2] {
    response(
        1,
        Sha256::new()
            .chain_update(b"aos.sandbox.root.delete-positive-completion.v2\0")
            .chain_update(acknowledgement)
            .finalize()
            .into(),
    )
}

/// Derives the Execution response from the original query, Root floor and ACK.
///
/// `floor_digest` is the referenced Root78 floor record digest carried by the
/// actual ACK's `root_floor`, rather than a hash of its signed attestation.
/// The exact canonical ACK bytes are committed here using the sole encoder.
/// Producing these comparison bytes creates no native ACK or financial proof.
#[must_use]
pub fn execution_no_apply_positive_completion_bytes_v2(
    query_digest: [u8; 32],
    floor_digest: [u8; 32],
    acknowledgement: ControllerCreateFailureAckDataV2,
) -> [u8; ROOT_POLICY_POSITIVE_COMPLETION_BYTES_V2] {
    response(
        2,
        Sha256::new()
            .chain_update(b"aos.sandbox.root.execution-no-apply-positive-completion.v2\0")
            .chain_update(query_digest)
            .chain_update(floor_digest)
            .chain_update(acknowledgement.encode_canonical())
            .finalize()
            .into(),
    )
}

fn response(purpose: u64, commitment: [u8; 32]) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[..8].copy_from_slice(b"AOSRPC02");
    bytes[8..16].copy_from_slice(&purpose.to_be_bytes());
    bytes[16..].copy_from_slice(&commitment);
    bytes
}

/// Selects the exact historical completion carried by a fresh Host inventory.
///
/// This comparison value never reconstructs the historical native Stop owner.
#[derive(Clone, Copy)]
pub enum StopCleanupObservationDataV1 {
    /// Carries the strict dual-boot completed historical namespace.
    Historical(crate::host_recovered_namespace::HostRecoveredNamespaceDataV7),
    /// Carries the strict completed cleanup child and its fresh observation.
    Cleanup(crate::host_cleanup_lineage::HostCleanupLineageDataV1),
}

/// Commits the sole canonical completed observation without issuing a new Stop.
///
/// # Errors
/// Rejects a historical row whose saved phase is not Complete, or a malformed
/// canonical row. Authentic MAC ancestry and native absence remain obligations
/// of the actual Host reader and the independent Root Session replay.
pub fn stop_cleanup_observation_decision_digest_v1(
    observation: StopCleanupObservationDataV1,
) -> Result<[u8; 32], crate::ProtocolValidationError> {
    use crate::host_cleanup_lineage::HostCleanupLineageDataV1;
    use crate::host_recovered_namespace::{
        HostRecoveredNamespaceDataV7, HostRecoveryStopPhaseDataV7,
    };

    let digest = Sha256::new().chain_update(b"aos.sandbox.root.stop-cleanup-observation.v1\0");
    Ok(match observation {
        StopCleanupObservationDataV1::Historical(row) => {
            let bytes = row.encode_v7();
            let row = HostRecoveredNamespaceDataV7::decode_v7(&bytes)?;
            if row.saved_phase_v7() != HostRecoveryStopPhaseDataV7::Complete {
                return Err(crate::ProtocolValidationError::InvalidField(
                    "incomplete historical Stop",
                ));
            }
            digest
                .chain_update(1_u64.to_be_bytes())
                .chain_update(bytes)
                .finalize()
                .into()
        }
        StopCleanupObservationDataV1::Cleanup(row) => {
            let bytes = row.encode_v1();
            HostCleanupLineageDataV1::decode_v1(&bytes)?;
            digest
                .chain_update(2_u64.to_be_bytes())
                .chain_update(bytes)
                .finalize()
                .into()
        }
    })
}

/// Derives the Stop response from its query, selected decision and final Host3.
///
/// The query commits the actual Recover reference, old Source dispatch and
/// fresh cleanup interval. An effect decision is the canonical456 subject's
/// `digest_data_v1`; an observation decision uses the helper above. The final
/// digest is the captured canonical signed Host3 outcome packet digest, not
/// a local journal head or the child request ID. These bytes grant no effect
/// or financial permission; only the private post-disposition writer gives
/// them their causal meaning on the same continuously held native connection.
#[must_use]
pub fn stop_cleanup_positive_completion_bytes_v1(
    query_digest: [u8; 32],
    decision_digest: [u8; 32],
    terminal_host_outcome_digest: [u8; 32],
) -> [u8; ROOT_POLICY_POSITIVE_COMPLETION_BYTES_V2] {
    response(
        3,
        Sha256::new()
            .chain_update(b"aos.sandbox.root.stop-cleanup-positive-completion.v1\0")
            .chain_update(query_digest)
            .chain_update(decision_digest)
            .chain_update(terminal_host_outcome_digest)
            .finalize()
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_confirmation_binds_query_decision_terminal_and_closed_purpose() {
        let expected = stop_cleanup_positive_completion_bytes_v1([1; 32], [2; 32], [3; 32]);

        assert_eq!(&expected[..8], b"AOSRPC02");
        assert_eq!(&expected[8..16], &3_u64.to_be_bytes());
        assert_ne!(
            expected,
            stop_cleanup_positive_completion_bytes_v1([4; 32], [2; 32], [3; 32])
        );
        assert_ne!(
            expected,
            stop_cleanup_positive_completion_bytes_v1([1; 32], [4; 32], [3; 32])
        );
        assert_ne!(
            expected,
            stop_cleanup_positive_completion_bytes_v1([1; 32], [2; 32], [4; 32])
        );
        assert_ne!(expected, response(1, expected[16..].try_into().unwrap()));
        assert_ne!(expected, response(2, expected[16..].try_into().unwrap()));
    }

    #[test]
    fn observation_decision_requires_complete_canonical_history() {
        use crate::host_inventory_absence::HostInventoryAbsenceDataV5;
        use crate::host_recovered_namespace::{
            HostRecoveredNamespaceDataV7, HostRecoveryStopPhaseDataV7,
        };
        use crate::host_stopped_namespace::HostStoppedNamespaceDataV4;

        let old = HostStoppedNamespaceDataV4::from_data_v4(
            [6; 16],
            crate::ValidatedAssignmentFence {
                sandbox_id: [1; 16],
                incarnation_id: [2; 16],
                assignment_epoch: 3,
                desired_generation: 4,
                assignment_digest: [5; 32],
            },
            [7; 32],
            ([8; 16], [9; 32], [10; 32]),
            ([11; 16], [12; 32], [13; 32]),
        )
        .unwrap();
        let observation =
            HostInventoryAbsenceDataV5::from_data_v5([14; 16], [15; 16], [16; 16], 17, 18).unwrap();
        let complete = HostRecoveredNamespaceDataV7::from_data_v7(
            old,
            observation,
            HostRecoveryStopPhaseDataV7::Complete,
        );
        let canonical = HostRecoveredNamespaceDataV7::decode_v7(&complete.encode_v7()).unwrap();
        let digest = stop_cleanup_observation_decision_digest_v1(
            StopCleanupObservationDataV1::Historical(canonical),
        )
        .unwrap();

        assert_ne!(digest, [0; 32]);
        for phase in [
            HostRecoveryStopPhaseDataV7::AuthorizedAbsent,
            HostRecoveryStopPhaseDataV7::PayloadPending,
        ] {
            let pending = HostRecoveredNamespaceDataV7::from_data_v7(old, observation, phase);
            assert!(
                stop_cleanup_observation_decision_digest_v1(
                    StopCleanupObservationDataV1::Historical(pending)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn delete_confirmation_commits_exact_ack_and_closed_purpose() {
        let first = delete_root_positive_completion_bytes_v2([1; 32]);
        let changed = delete_root_positive_completion_bytes_v2([2; 32]);

        assert_eq!(&first[..8], b"AOSRPC02");
        assert_eq!(&first[8..16], &1_u64.to_be_bytes());
        assert_ne!(first, changed);
        assert_ne!(first, response(2, first[16..].try_into().unwrap()));
    }

    #[test]
    fn execution_confirmation_binds_query_floor_and_entire_canonical_ack() {
        use crate::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2;
        use crate::domain_ledger::protected_names::ProtectedJournalNamesV1;
        use crate::host_execution_no_apply::closed_controller::ControllerCreateFailureAckPhaseV2;
        use aos_sandbox_core::{ObjectDigest, OperationId};

        let ack = ControllerCreateFailureAckDataV2 {
            operation: OperationId::from_bytes([1; 16]),
            root_floor: ObjectDigest::from_bytes([2; 32]),
            root_sequence: 3,
            controller_prepare: ObjectDigest::from_bytes([4; 32]),
            settled_cas: ObjectDigest::from_bytes([5; 32]),
            phase: ControllerCreateFailureAckPhaseV2::Active,
            controller_cut: RootExecutionNoApplyControllerCutDataV2::from_rows_data_v2(
                ProtectedJournalNamesV1::from_historical_fields((1, 2), (1, 3), (1, 4)),
                108,
                4096,
                std::iter::empty(),
            )
            .unwrap(),
        };
        let canonical = ack.encode_canonical();
        let decoded = ControllerCreateFailureAckDataV2::decode_canonical(&canonical).unwrap();
        let expected = execution_no_apply_positive_completion_bytes_v2([6; 32], [2; 32], decoded);

        assert_eq!(&expected[8..16], &2_u64.to_be_bytes());
        assert_ne!(
            expected,
            execution_no_apply_positive_completion_bytes_v2([7; 32], [2; 32], ack)
        );
        assert_ne!(
            expected,
            execution_no_apply_positive_completion_bytes_v2([6; 32], [7; 32], ack)
        );
        for changed in [
            ControllerCreateFailureAckDataV2 {
                root_sequence: 4,
                ..ack
            },
            ControllerCreateFailureAckDataV2 {
                settled_cas: ObjectDigest::from_bytes([7; 32]),
                ..ack
            },
            ControllerCreateFailureAckDataV2 {
                phase: ControllerCreateFailureAckPhaseV2::RecoverySettled,
                ..ack
            },
        ] {
            assert_ne!(
                expected,
                execution_no_apply_positive_completion_bytes_v2([6; 32], [2; 32], changed)
            );
        }
    }
}

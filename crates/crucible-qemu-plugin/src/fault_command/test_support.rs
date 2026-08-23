//! Test-only result fixtures for the fault-command transport.

use super::{FaultResultStatus, QemuFaultCommand, QemuFaultResult};

pub(super) fn test_result_for_command(command: QemuFaultCommand) -> QemuFaultResult {
    QemuFaultResult {
        command_kind: command.command_kind,
        status: FaultResultStatus::Applied as u16,
        phase: command.phase,
        reserved: 0,
        semantic_version: command.semantic_version,
        capability_version: 1,
        command_sequence: command.command_sequence,
        observed_icount: command.target_icount,
        applied_icount: command.target_icount,
        before_hash: [0; 32],
        after_hash: [0; 32],
        evidence_hash: [0; 32],
    }
}

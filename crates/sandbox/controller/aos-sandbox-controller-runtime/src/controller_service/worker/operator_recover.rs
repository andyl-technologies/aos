//! Serves only explicit operator recovery after a confirmed recipient transfer.
//!
//! The parent retains its ordinary paid startup and TLS originals. This worker
//! does not reconstruct initial operation intakes, reconcile effects, discover
//! inventory, publish a catalog, or report ordinary Controller readiness.

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use super::super::commands::{ControllerCommand, ControllerCommandFailure};
use super::super::resident_custody::{
    ControllerResidentCauseV1, ControllerWorkerCustodyV1, ControllerWorkerLoanV1,
};
use super::{WorkerEvent, handle_controller_command};

/// Keeps the same resident Controller available for separately admitted recovery.
pub(super) fn run<'worker>(
    loan: ControllerWorkerLoanV1<'worker>,
    custody: Option<&ControllerWorkerCustodyV1>,
) -> Option<ControllerWorkerLoanV1<'worker>> {
    let Some(custody) = custody else {
        // Only the parent that owns confirmed successor startup may select this
        // disposition. Ordinary consuming activation cannot enter it.
        std::process::abort();
    };
    let (Some(bank), Some(profile), Some(runtime)) = (
        loan.resource_bank,
        loan.profile_original,
        loan.shared_runtime,
    ) else {
        custody.terminate(ControllerResidentCauseV1::Closed(
            "operator recovery requires the same startup bank, profile and runtime",
        ));
    };
    if let Err(cause) = loan.events.send(WorkerEvent::RecoveryListening) {
        custody.terminate(ControllerResidentCauseV1::ReadySend(cause));
    }

    loop {
        if custody.ended.load(Ordering::Acquire) {
            return None;
        }
        let command = match loan.commands.recv_timeout(Duration::from_millis(250)) {
            Ok(command) => command,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                custody.terminate(ControllerResidentCauseV1::Closed(
                    "operator recovery command channel disconnected",
                ));
            }
        };
        if custody.ended.load(Ordering::Acquire) {
            // A returned command can own native inputs; retain it across the
            // terminal fence instead of dropping an unexamined original.
            let _command = command;
            custody.terminate(ControllerResidentCauseV1::Closed(
                "operator recovery command arrived after termination",
            ));
        }
        let Some(command) = recovery_command(command) else {
            continue;
        };
        if let Err(message) = handle_controller_command(
            loan.controller,
            loan.ownership,
            loan.attach,
            loan.signer,
            aos_sandbox_model::NodeId::from_bytes(loan.node),
            loan.sessions,
            command,
            Some((bank, profile, runtime)),
        ) {
            custody.terminate(ControllerResidentCauseV1::Worker(message));
        }
        if let Some(context) = loan.controller.take_recovered_ordinary_sessions_once_v2() {
            let Some(foundations) = loan.foundations else {
                let _context = context;
                custody.terminate(ControllerResidentCauseV1::Closed(
                    "recovered Sessions require the same startup foundations",
                ));
            };
            let Ok(mut sessions) = loan.sessions.lock() else {
                let _context = context;
                custody.terminate(ControllerResidentCauseV1::Closed(
                    "recovered Session context lock poisoned",
                ));
            };
            if let Err(context) = super::super::initial_broker_sessions::install_recovered_context_v2(
                &mut sessions, context, bank, profile, runtime, foundations,
            ) {
                let _context = context;
                custody.terminate(ControllerResidentCauseV1::Closed(
                    "recovered Session context installation refused",
                ));
            }
            drop(sessions);
            // The same mutable worker loan enters the sole ordinary loop.
            // Recover startup, read-only Sessions and enrollment stay resident
            // in its executor; this transition itself emits no Ready event.
            return Some(loan);
        }
    }
}

// This filter grants no recovery authority. The same actual command handler
// must enter the native owner and authenticate the capability and request.
fn recovery_command(command: ControllerCommand) -> Option<ControllerCommand> {
    macro_rules! unavailable {
        ($reply:expr) => {
            let _ = $reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
        };
    }

    match command {
        command @ ControllerCommand::AdmitPublicOperatorRecovery { .. } => Some(command),
        ControllerCommand::BootstrapPublicCapability { reply, .. } => {
            unavailable!(reply);
            None
        }
        ControllerCommand::GetOperation { reply, .. }
        | ControllerCommand::GetAuthorizedOperation { reply, .. } => {
            unavailable!(reply);
            None
        }
        ControllerCommand::AuthorizePublicRead { reply, .. } => {
            unavailable!(reply);
            None
        }
        ControllerCommand::ReadPublicProjection { reply, .. } => {
            unavailable!(reply);
            None
        }
        ControllerCommand::PlanPublicPolicy { reply, .. } => {
            unavailable!(reply);
            None
        }
        ControllerCommand::AdmitPublicMutation { reply, .. } => {
            unavailable!(reply);
            None
        }
        ControllerCommand::AdmitPublicAttach { reply, .. } => {
            unavailable!(reply);
            None
        }
        ControllerCommand::ResolvePublicCapabilityTarget { reply, .. } => {
            unavailable!(reply);
            None
        }
        command @ ControllerCommand::InspectGitRead { .. } => {
            // Git ingress is never installed in this mode. A violated internal
            // route may carry an original owner, which must survive failure.
            let _command = command;
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn ordinary_operation_reads_receive_unavailable_without_dispatch() {
        let (reply, mut response) = tokio::sync::oneshot::channel();
        let command = ControllerCommand::GetOperation {
            operation_id: aos_sandbox_model::OperationId::from_bytes([1; 16]),
            expires_at: Instant::now(),
            reply,
        };

        assert!(recovery_command(command).is_none());

        assert!(matches!(
            response.try_recv(),
            Ok(Err(ControllerCommandFailure::ControllerUnavailable))
        ));
    }
}

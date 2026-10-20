//! Shared Storage service outcomes and fail-stop response disposition.
//!
//! Authenticated broker sessions are assembled by the separately packaged
//! service. This module retains error/outcome types used by its startup and
//! side transports, plus the response fail-stop helper used by qualification.

use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::bounded::BoundedRecordError;
use aos_sandbox_protocol::ProtocolValidationError;

use crate::runtime::StorageRuntimeError;

#[cfg(test)]
mod legacy_envelope_profile;

/// Classifies handling of one accepted Storage connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageConnectionOutcome {
    /// One repair or authoritative inventory request completed successfully.
    Served,
    /// The connection or a record did not name the configured controller.
    PeerRejected,
    /// A verified peer sent an invalid request or received a bounded safe error.
    RequestRejected,
    /// The accepted child failed its bounded packet exchange.
    TransportRejected,
}

/// Reports fatal Storage service construction, clock, or transport failure.
#[derive(Debug, thiserror::Error)]
pub enum StorageServiceError {
    /// The record-subject carrier failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// A retained cgroup, pidfd, or protected filesystem operation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// A protocol value produced internally violated the closed schema.
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    /// Protected Storage runtime construction or reconciliation failed.
    #[error(transparent)]
    Runtime(#[from] StorageRuntimeError),
    /// A local poll operation failed.
    #[error("Storage service kernel I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
    /// `CLOCK_BOOTTIME` or its paired wall observation was invalid.
    #[error("Storage service kernel clock observation is invalid")]
    Clock,
    /// Process startup did not provide the exact fixed activation contract.
    #[error("Storage service activation is invalid: {0}")]
    Activation(String),
    /// The signed LocalLive request or its current physical publication failed.
    #[error("Storage live-export signed readback is unavailable")]
    LiveExportReadback,
}

impl From<BoundedRecordError> for StorageServiceError {
    fn from(error: BoundedRecordError) -> Self {
        match error {
            BoundedRecordError::Transport(error) => Self::Transport(error),
            BoundedRecordError::Io(error) => Self::Io(error),
            BoundedRecordError::Clock => Self::Clock,
        }
    }
}

pub(crate) fn finish_dispatched_response(
    reopen_required: bool,
    response_sent: bool,
    outcome: StorageConnectionOutcome,
) -> Result<StorageConnectionOutcome, StorageServiceError> {
    // Once custody is ambiguous, even a failed response send must not return to
    // the accept loop. Exiting lets systemd reopen and replay protected state.
    if reopen_required {
        return Err(StorageRuntimeError::ReopenRequired.into());
    }
    if !response_sent {
        return Ok(StorageConnectionOutcome::TransportRejected);
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn reopen_required_exits_after_bounded_response_handling() {
        for response_sent in [false, true] {
            let error = finish_dispatched_response(
                true,
                response_sent,
                StorageConnectionOutcome::RequestRejected,
            )
            .unwrap_err();

            assert!(matches!(
                error,
                StorageServiceError::Runtime(StorageRuntimeError::ReopenRequired)
            ));
        }

        assert_eq!(
            finish_dispatched_response(false, true, StorageConnectionOutcome::RequestRejected,)
                .unwrap(),
            StorageConnectionOutcome::RequestRejected
        );
        assert_eq!(
            finish_dispatched_response(false, false, StorageConnectionOutcome::RequestRejected,)
                .unwrap(),
            StorageConnectionOutcome::TransportRejected
        );
    }
}

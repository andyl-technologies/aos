//! Borrows the entered checkpoint original across bounded QMP I/O.
//!
//! The caller retains the actual original and its cancellation subscriber.
//! Every I/O slice checks that same subscriber; an exchange never completes
//! the whole capture or reports a pending poll as required-work progress.
//! This transport loan cannot issue a native transaction or capture readiness.

use super::*;
use crucible_host_resources::host_supervision::HostSupervisionError;

/// Retains the initiating exchange cause and independent original postcut.
#[derive(Debug, thiserror::Error)]
#[error("{source}; checkpoint original postcut: {original_after:?}")]
pub(super) struct CheckpointExchangeError {
    /// Initiating typed QMP or original-boundary refusal.
    #[source]
    pub(super) source: QmpError,
    /// Independent SAME original refusal after the attempted exchange.
    pub(super) original_after: Option<HostSupervisionError>,
}

fn checked_slice(original: &HostOperationGuard) -> Result<Duration, HostSupervisionError> {
    original.check_original_quiescence_cancellation()?;
    let slice = original.wait_slice()?;
    original.check_original_quiescence_cancellation()?;
    Ok(slice)
}

/// Returns the retained checkpoint original's responsive I/O slice.
///
/// # Errors
/// Refuses the original class, subscriber, cancellation, expiration or policy.
pub(super) fn wait_slice(
    original: &HostOperationGuard,
    operation: &'static str,
) -> Result<Duration, QmpError> {
    checked_slice(original).map_err(|source| QmpError::CheckpointOriginal { operation, source })
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Exchanges a typed command under the caller's retained checkpoint original.
    ///
    /// This loans transport only. The real receiving command and native held
    /// transaction are not implemented by this helper; no request is invented.
    ///
    /// # Errors
    /// Refuses unusable transport, the actual original or I/O/response parsing.
    /// Uncertain writes/responses poison the cursor; the first cause survives
    /// any independently observed original postcut.
    pub(super) fn exchange_under_checkpoint_original(
        &mut self,
        command: QmpCommand<'_>,
        original: &HostOperationGuard,
    ) -> Result<QmpCommandReturn, CheckpointExchangeError> {
        let operation = command.kind().wire_name();
        let work = self.checkpoint_exchange(command, original);
        let original_after = checked_slice(original).err();
        if original_after.is_some() {
            self.poison_checkpoint_exchange();
        }
        match (work, original_after) {
            (Err(source), original_after) => Err(CheckpointExchangeError {
                source,
                original_after,
            }),
            (Ok(_), Some(source)) => {
                self.poison_checkpoint_exchange();
                Err(CheckpointExchangeError {
                    source: QmpError::CheckpointOriginal { operation, source },
                    original_after: Some(source),
                })
            }
            (Ok(response), None) => Ok(response),
        }
    }

    pub(super) fn poison_checkpoint_exchange(&mut self) {
        self.poisoned = true;
        self.stream.get_mut().poison_qmp_stream();
    }

    fn checkpoint_exchange(
        &mut self,
        command: QmpCommand<'_>,
        original: &HostOperationGuard,
    ) -> Result<QmpCommandReturn, QmpError> {
        self.ensure_usable()?;
        let kind = command.kind();
        let deadline = QmpOperationDeadline {
            supervision: None,
            timeout: self.io_timeout_policy.command_timeout,
            shared: None,
            checkpoint_original: Some(original),
            checkpoint_loan: None,
            borrowed: None,
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            paired: None,
            _lifetime: std::marker::PhantomData,
        };
        deadline.remaining(kind.wire_name())?;
        if let Err(first) = self.write_json_line(kind.wire_name(), command.request(), &deadline) {
            self.poison_checkpoint_exchange();
            return Err(first);
        }
        let response = match self.read_command_response(kind, &deadline) {
            Ok(response) => response,
            Err(first) => {
                if !matches!(first, QmpError::Command { .. }) {
                    self.poison_checkpoint_exchange();
                }
                return Err(first);
            }
        };
        if let Err(first) = deadline.complete(kind.wire_name()) {
            self.poison_checkpoint_exchange();
            return Err(first);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests;

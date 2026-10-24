//! Borrows the same committed Prepare outcome through the genuine C9 transport.
//!
//! This adapter neither clones the signed packets nor constructs a Session,
//! bank claim, deadline or native history success from decoded DATA.

use super::*;
use std::error::Error;

/// Keeps the actual completion or transport leaf without flattening its cause.
#[derive(Debug, thiserror::Error)]
pub(super) enum OutcomeExchangeErrorV1 {
    #[error("the original Prepare terminal is incomplete")]
    Completion(#[source] OutputPreparationClosedV1),
    #[error("the same C9 Root outcome transport did not complete")]
    Transport(#[source] aos_sandbox_controller_domain::CreateStorageRootExchangeClosedV1),
}

impl OriginalStorageCreatePreparationFlightV1 {
    /// Exchanges only this retained completed Prepare outcome on its actual Ready.
    pub(crate) fn exchange_outcome_once(&mut self,
        ready: &mut aos_sandbox_controller_domain::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> bool {
        if self.use_first.is_some() || self.outcome_exchanged.is_some() {
            return self.close_use(UsePreparationFailureV1::Closed);
        }
        self.outcome_exchanged = Some(match self.committed_prepare_outcome_v1() {
            Ok(outcome) => ready.exchange_original_storage_outcome_once(outcome)
                .map_err(OutcomeExchangeErrorV1::Transport),
            Err(cause) => Err(OutcomeExchangeErrorV1::Completion(cause)),
        });
        if matches!(self.outcome_exchanged, Some(Ok(()))) { true }
        else { self.close_use(UsePreparationFailureV1::OutcomeExchange) }
    }

    /// Borrows the selected actual leaf while all native originals remain held.
    pub(super) fn outcome_exchange_failure_v1<'cause>(&'cause self,
        ready: &'cause aos_sandbox_controller_domain::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> Option<&'cause (dyn Error + 'static)> {
        match self.outcome_exchanged.as_ref()?.as_ref().err()? {
            OutcomeExchangeErrorV1::Completion(cause) => Some(cause),
            OutcomeExchangeErrorV1::Transport(cause) => ready.original_root_exchange_failure()
                .or(Some(cause as _)),
        }
    }
}

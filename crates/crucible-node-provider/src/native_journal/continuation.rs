//! Authenticated poll progress within one immutable original running operation.
//!
//! A continuation consumes a distinct original poll request, not another begin
//! permit. Unknown effects retain their original locks and cannot use this path.

use crate::bodies::OperationState;
use crate::envelope::{MessageKind, Method};

use super::*;

/// Authenticates native progress before a bounded continuation of the original grant.
pub trait NativeContinuationVerifier<C: 'static> {
    /// Verifies the retained prefix, unchanged input closure, and original scope.
    ///
    /// Implementations belong to installed native adapters. The operation's
    /// original grant remains immutable; a poll supplies no replacement bounds.
    ///
    /// # Errors
    /// Rejects uncertain or foreign native custody, unreleased publications,
    /// changed inputs, invalid owner frontiers, and incomplete native evidence.
    fn verify_continuation(
        &self,
        resources: &C,
        original: &OperationSnapshot,
        poll: &Envelope,
    ) -> Result<(), ProviderError>;
}

impl<C: 'static> NativeJournal<C> {
    /// Services one authenticated poll within its still-running original operation.
    ///
    /// The poll's one-shot request reservation prevents retries from performing
    /// another prefix. Native errors and unwinding preserve unknown operation
    /// custody; no new begin, owner activation, or grant is issued.
    ///
    /// # Errors
    /// Rejects foreign or revoked authority, reused poll permits, mismatched
    /// original operation identity or owner scope, non-running operations, and
    /// failed installed native validation. Native callback errors retain locks.
    pub fn with_running_operation_resources<T>(
        &mut self,
        authority: &ConnectionAuthority,
        permit: &NativeRequestPermit,
        verifier: &dyn NativeContinuationVerifier<C>,
        effect: impl FnOnce(&mut C) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        self.check_authority(authority)?;
        self.check_request_permit(permit)?;
        let request =
            self.custody()
                .reservations
                .get(&permit.key)
                .ok_or(ProviderError::Correlation(
                    "original poll reservation absent",
                ))?;
        if request.started
            || request.original.method != Method::Poll
            || request.original.message != MessageKind::Request
        {
            return Err(ProviderError::Conflict(
                "continuation requires an unstarted original poll",
            ));
        }
        let poll = request.original.clone();
        let RequestBody::Poll(_) = bodies::decode_request(Method::Poll, &poll.body)? else {
            return Err(ProviderError::Frame("continuation poll body differs"));
        };
        let operation = poll
            .operation_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "continuation poll lacks original operation identity",
            ))?;
        let original =
            self.custody()
                .operations
                .get(operation)
                .ok_or(ProviderError::Correlation(
                    "continuation original operation absent",
                ))?;
        if original.state != OperationState::Running
            || original.cancel_requested
            || original.retired
            || original.domains_released
            || original.outcome.is_some()
            || poll.execution_owner_id.0.as_ref() != Some(&original.scope.execution_owner)
        {
            return Err(ProviderError::Conflict(
                "original operation cannot admit further progress",
            ));
        }
        verifier.verify_continuation(self.resources(), original, &poll)?;

        let operation = operation.clone();
        authority.with_live(|| {
            // Consume the one-shot poll and retain uncertainty atomically with
            // fencing. This callback only records bounded local admission.
            self.with_request_resources(permit, |_| Ok(()))?;
            self.custody_mut()
                .operations
                .get_mut(&operation)
                .ok_or(ProviderError::Correlation(
                    "continuation operation disappeared",
                ))?
                .state = OperationState::Unknown;
            Ok(())
        })?;

        // Native execution and socket I/O must never hold the registration gate.
        // Errors and unwinding retain Unknown and the original native resources.
        let value = effect(&mut self.custody_mut().resources)?;
        authority.with_live(|| {
            self.custody_mut()
                .operations
                .get_mut(&operation)
                .ok_or(ProviderError::Correlation(
                    "continuation operation disappeared",
                ))?
                .state = OperationState::Running;
            Ok(())
        })?;
        Ok(value)
    }
}

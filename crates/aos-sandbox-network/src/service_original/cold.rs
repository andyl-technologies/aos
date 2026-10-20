//! Lends the genuine Network startup's original cold Session inputs once.

use super::*;
use aos_sandbox_broker::receiving::{FixedServiceOperationOriginalV4, NetworkServiceSessionOpeningLoanV4};

/// Borrows the actual fixed Session, listener and protected public-file owners.
///
/// The same service constructs this lender only after its independent startup
/// posts. It exposes no raw Journal, descriptor, secret, principal, account or
/// replacement origin; each native capture permits only its original handoff.
pub struct NetworkServiceSessionInputsV4<'held> {
    session: &'held mut NetworkBrokerSessionCapturedJournalOpenV4,
    listener: &'held mut FixedServiceListenerOriginalV4,
    credentials: &'held ProtectedBrokerPublicCredentials,
}

impl NetworkServiceSessionInputsV4<'_> {
    /// Borrows the owning inputs consumed by the shared fixed cold engine.
    pub fn fixed_originals_v4(&mut self) -> (
        &mut NetworkBrokerSessionCapturedJournalOpenV4,
        &mut FixedServiceListenerOriginalV4,
        &ProtectedBrokerPublicCredentials,
    ) {
        (self.session, self.listener, self.credentials)
    }
}

impl NetworkServiceOriginalV4 {
    /// Enters the distinct same-F Network cold interval over its real originals.
    ///
    /// The shared SDK cold constructor owns body marking and unconditional F
    /// closure after this entry. The installed caller retains both whole owners
    /// and drops only these short views when that constructor returns.
    ///
    /// # Errors
    /// Refuses incomplete startup, repeated input handoff, absent credentials,
    /// checked header geometry or the actual fixed-role financial/native gate.
    pub fn borrow_session_opening_once_v4<'held>(&'held mut self,
        operation: &'held mut FixedServiceOperationOriginalV4, fixed: ResourceVector)
        -> Result<(NetworkServiceSessionOpeningLoanV4<'held>, NetworkServiceSessionInputsV4<'held>)> {
        self.require_ready_v4()?;
        if self.cold_borrowed { return Err(NetworkServiceClosedV4); }
        self.cold_borrowed = true;
        self.geometry = Some((|| {
            let bytes = std::mem::size_of::<NetworkServiceSessionInputsV4<'_>>().checked_mul(2)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            fixed.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        let fixed = self.geometry.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(NetworkServiceClosedV4)?;
        let credentials = self.credentials.as_ref().ok_or(NetworkServiceClosedV4)?;
        let loan = self.common.begin_network_session_opening_once_v4(operation, fixed)
            .map_err(|_| NetworkServiceClosedV4)?;
        Ok((loan, NetworkServiceSessionInputsV4 { session: &mut self.session_opening,
            listener: &mut self.listener_opening, credentials }))
    }

    /// Borrows only the actual captured Session original's selected error.
    #[must_use]
    pub fn captured_session_failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        self.session_opening.failure()
    }

    /// Borrows only the supplied operation's same-Common original first cause.
    #[must_use]
    pub fn operation_failure_v4<'held>(&'held self, operation: &'held FixedServiceOperationOriginalV4)
        -> Option<&'held (dyn Error + 'static)> {
        operation.failure_with_common_v4(&self.common)
    }
}

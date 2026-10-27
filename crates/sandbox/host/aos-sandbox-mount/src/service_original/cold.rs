//! Lends only the actual captured Mount Session/listener to its cold opener.

use aos_sandbox_broker::receiving::{FixedServiceOperationOriginalV4,
    MountServiceSessionOpeningLoanV4};
use super::*;

/// Lends the same funded fixed-role originals without a raw Journal getter.
///
/// Only the actual Mount service constructs this lender after its complete
/// native startup. The protected SDK consumes the successful Journal and
/// listener directly from these owning captures, before its next fallible
/// native operation. Partial captures, public Files and original lineage stay
/// with the same service/SDK owners on every refusal.
pub struct MountServiceSessionInputsV4<'held> {
    session: &'held mut MountBrokerSessionCapturedJournalOpenV4,
    listener: &'held mut FixedServiceListenerOriginalV4,
    credentials: &'held ProtectedBrokerPublicCredentials,
}

impl MountServiceSessionInputsV4<'_> {
    /// Borrows the three actual typed owners for the sole fixed cold recipe.
    ///
    /// This returns no Journal, raw descriptor, key seed, role selector,
    /// callback or completion assertion. Each owning capture permits only its
    /// existing once-only positive transfer under the genuine opening loan.
    pub fn fixed_originals_v4(&mut self) -> (
        &mut MountBrokerSessionCapturedJournalOpenV4,
        &mut FixedServiceListenerOriginalV4,
        &ProtectedBrokerPublicCredentials,
    ) {
        (self.session, self.listener, self.credentials)
    }
}

impl MountAttachmentAnchorServiceOriginalV4 {
    /// Enters the distinct same-F cold Session interval and lends its originals.
    ///
    /// The caller must prepay its actual complete SDK cold header/geometry and
    /// run the opening loan's independent native after on every entered path.
    /// This constructor supplies no Session or effect authority.
    ///
    /// # Errors
    /// Refuses incomplete startup, repeated handoff, missing actual credentials
    /// or the same original financial/native admission.
    pub fn borrow_session_opening_once_v4<'held>(
        &'held mut self,
        operation: &'held mut FixedServiceOperationOriginalV4,
        fixed: ResourceVector,
    ) -> Result<(MountServiceSessionOpeningLoanV4<'held>, MountServiceSessionInputsV4<'held>)> {
        self.require_service_ready()?;
        if self.cold_borrowed {
            self.first.get_or_insert(Failure::Order);
            return Err(closed("Mount fixed Session handoff cannot reenter"));
        }
        self.cold_borrowed = true;
        self.callsite_geometry = Some((|| {
            use aos_sandbox_model::ResourceDimension as D;
            let bytes = std::mem::size_of::<MountServiceSessionInputsV4<'_>>().checked_mul(2)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
            fixed.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        let fixed = match self.callsite_geometry.as_ref().and_then(|value| value.as_ref().ok()).copied() {
            Some(fixed) => fixed,
            None => {
                self.first.get_or_insert(Failure::Geometry);
                return Err(closed("Mount cold lender geometry refused"));
            }
        };
        let credentials = self.credentials.as_ref()
            .ok_or_else(|| closed("Mount original credential pins are absent"))?;
        let loan = self.common.begin_mount_session_opening_once_v4(operation, fixed)
            .map_err(|_| closed("Mount original cold Session receiving refused"))?;
        Ok((loan, MountServiceSessionInputsV4 {
            session: &mut self.session_opening,
            listener: &mut self.listener_opening,
            credentials,
        }))
    }
}

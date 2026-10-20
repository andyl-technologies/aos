//! Runs Recover's fixed cold opener through the sole native capture engine.
//!
//! The same actual Recover loan remains borrowed through this capture and the
//! later Inventory. Its original C/Source posts remain independently owed.
//! This owner never adopts, retires or overwrites an earlier Apply Session.

use super::*;
use aos_sandbox_controller_domain::ResourceReservationErrorV1;
use super::ColdLoanV2;
use aos_sandbox_model::{ResourceDimension, ResourceVector, RawPairedClockSample};

/// Retains the distinct authorized Recover Inventory18 cold-open originals.
///
/// Empty construction performs no admission or IO. The installed caller parks
/// this whole owner before entry and retains it beside the real Recover owner
/// on every refusal, including its enclosing independently owed C/Source posts.
#[doc(hidden)]
#[must_use = "retain the whole Recover capture beside its same original"]
#[derive(Default)]
pub(super) struct RecoverColdSessionOpenV2 {
    preparation: Option<Result<(), ResourceReservationErrorV1>>,
    before: Option<Result<RawPairedClockSample, ResourceReservationErrorV1>>,
    inner: Option<handshake::ControllerInitialSessionOpenV1>,
    result: Option<Result<(), BrokerSessionSecurityError>>,
    after: Option<Result<RawPairedClockSample, ResourceReservationErrorV1>>,
    reentry: bool,
    taken: bool,
}

impl RecoverColdSessionOpenV2 {
    /// Enters the genuine Recover-funded cold capture once.
    ///
    /// # Errors
    /// Retains expiry, native admission, handshake, full replay and post causes.
    /// An error never removes the original SDK or native capture destinations.
    pub(super) fn open_once_v2(&mut self, mut loan: ColdLoanV2<'_, '_, '_, '_, '_, '_, '_, '_, '_>,
        launch_image: crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.preparation.is_some() || self.reentry {
            self.reentry = true;
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.preparation = Some((|| {
            let bytes = std::mem::size_of::<Self>().checked_mul(3)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            loan.reserve_additional_v2(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))?;
            self.before = Some(loan.check_frontier_v2());
            if !matches!(self.before, Some(Ok(_))) { return Err(ResourceReservationErrorV1::Conflict); }
            let shape = handshake::ControllerInitialSessionOpenV1::receiving_shape_v1(
                loan.role_v2(),
            ).ok_or(ResourceReservationErrorV1::Conflict)?;
            loan.prepare_session_once_v2(shape)?;
            let receiving = loan.take_session_receiver_once_v2()?;
            self.inner = Some(handshake::ControllerInitialSessionOpenV1::new(receiving, Some(launch_image)));
            Ok(())
        })());
        self.result = Some(if matches!(self.preparation, Some(Ok(()))) {
            match self.inner.as_mut() {
                Some(inner) => inner.open_once().map_err(|_| BrokerSessionSecurityError::Currentness),
                None => Err(BrokerSessionSecurityError::Currentness),
            }
        } else { Err(BrokerSessionSecurityError::Currentness) });
        // This independent original-clock frontier follows either entered
        // outcome. It cannot replace the earlier capture or SDK primary.
        if !matches!(self.result, Some(Ok(()))) {
            loan.retain_sdk_refusal_once_v2();
        }
        if self.before.is_some() {
            self.after = Some(loan.observe_owed_clock_after_once_v2());
        }
        self.require_complete_v1()
    }

    fn require_complete_v1(&self) -> Result<(), BrokerSessionSecurityError> {
        if !self.reentry && matches!(self.preparation, Some(Ok(())))
            && matches!(self.before, Some(Ok(_))) && matches!(self.result, Some(Ok(())))
            && matches!(self.after, Some(Ok(_)))
            && self.inner.as_ref().is_some_and(|inner| inner.failure().is_none())
        { Ok(()) } else { Err(BrokerSessionSecurityError::Currentness) }
    }

    /// Moves the authenticated observation Session after its actual cold posts.
    ///
    /// The caller retains this capture and the enclosing Recover loan while
    /// Inventory and the final Source/C posts run; this is not public acceptance.
    #[must_use]
    pub fn take_completed_once_v1(&mut self) -> Option<DormantAuthenticatedBrokerSessionV1> {
        if self.taken || self.require_complete_v1().is_err() { return None; }
        let session = self.inner.as_mut()?.take_completed()?;
        self.taken = true;
        Some(DormantAuthenticatedBrokerSessionV1(session, Vec::new()))
    }

    pub(super) fn borrow_completed_kernel_session_v1<'held>(&'held self,
        session: &'held mut handshake::DormantAuthenticatedBrokerSessionV1,
    ) -> Result<handshake::ControllerInitialSessionCompletedBorrowV1<'held>, BrokerSessionSecurityError> {
        self.require_complete_v1()?;
        self.inner.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?
            .borrow_completed_session_v1(session)
    }

    /// Borrows the first retained SDK/native capture failure.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.preparation.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.inner.as_ref().and_then(|inner| inner.failure()))
            .or_else(|| self.result.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.after.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.reentry.then_some(&BrokerSessionSecurityError::Currentness as &(dyn std::error::Error + 'static)))
    }
}

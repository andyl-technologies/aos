//! Retires the same failed original world without depending on a capture archive.
//!
//! Complete source/model/native/private-ACK histories are durably retained before
//! the first Shutdown hook. Both custodians keep original credit until actual
//! protocol/reaping proof, original refusal/signature and fresh complete roots
//! authorize release. Every refusal retains the same owning Worker/capsule.

use super::super::super::super::{NodeObservationServiceError, refused};
use super::Worker;
use crucible::node_contract::{
    GracefulRetirementQualification, NodeRuntime, QuarantinedRuntime, RuntimeError, WorldActivation,
};
use std::task::{Context, Poll, Waker};

pub(super) struct FailureCleanup {
    shutdown_started: bool,
    original: Option<QuarantinedRuntime>,
    history_verified: bool,
    transferred: bool,
    source: Option<crate::node_observed_executor::factory::OriginalFailedSupervision>,
    supervised: bool,
    sealed: Option<super::super::super::ledger::failed_retirement::SealedFailedRetirement>,
    released: Option<crate::node_observed_executor::factory::OriginalFailedNativeRelease>,
}

impl FailureCleanup {
    pub(super) fn new() -> Self {
        Self {
            shutdown_started: false,
            original: None,
            history_verified: false,
            transferred: false,
            source: None,
            supervised: false,
            sealed: None,
            released: None,
        }
    }
}

impl Worker {
    pub(super) fn reconcile_failed_original(
        &mut self,
    ) -> Result<bool, NodeObservationServiceError> {
        // Only a genuinely published fresh original has this independently
        // selected prebirth holder. Inactive/partial/Continue worlds stay held.
        if self.failure_retirement.is_none()
            || self.activation.is_none()
            || self.preservation.is_none()
            || self.target.is_none()
        {
            return Ok(false);
        }
        if !self.failure_cleanup.shutdown_started {
            let original = self
                .failure_retirement
                .as_ref()
                .ok_or_else(|| refused("original failure holder absent"))?;
            original
                .authenticate_failure_history(self.blobs.as_ref(), self.refs.as_ref())
                .map_err(refused)?;
            self.preservation
                .as_ref()
                .ok_or_else(|| refused("original failure factory absent"))?
                .authenticate_failure_retirement(original)
                .map_err(refused)?;
            // The whole-purpose latch precedes even unsupported adapter reads.
            // Unwind retains the same world in its preallocated original slot;
            // this sticky start flag never retries a first Shutdown attempt.
            self.failure_cleanup.shutdown_started = true;
            self.failure_cleanup.original =
                Some(NodeRuntime::take_graceful_retirement(&mut self.runtime).map_err(refused)?);
        }
        let Some(retired) = self.failure_cleanup.original.as_mut() else {
            return Ok(false);
        };
        if retired.shutdown_failure().is_some() {
            return Ok(false);
        }
        let mut context = Context::from_waker(Waker::noop());
        match retired.poll_reclamation(&mut context) {
            Poll::Pending => return Ok(false),
            Poll::Ready(Err(error)) => return Err(refused(error)),
            Poll::Ready(Ok(())) => {}
        }
        let activation = self
            .activation
            .as_ref()
            .ok_or_else(|| refused("original actual activation absent"))?;
        let original = self
            .failure_retirement
            .as_mut()
            .ok_or_else(|| refused("original failure holder absent"))?;
        if !self.failure_cleanup.history_verified {
            original
                .authenticate_retired_failure(
                    retired,
                    activation,
                    self.blobs.as_ref(),
                    self.refs.as_ref(),
                )
                .map_err(refused)?;
            self.failure_cleanup.history_verified = true;
        }
        if !self.failure_cleanup.transferred {
            retired.transfer_retirement_resources().map_err(refused)?;
            self.failure_cleanup.transferred = true;
        }
        let policy = self
            .preservation
            .as_ref()
            .ok_or_else(|| refused("original installed cleanup policy absent"))?;
        let target = self
            .target
            .as_ref()
            .ok_or_else(|| refused("original native target absent"))?;
        if self.failure_cleanup.released.is_none() && !policy.reclaimed(target).map_err(refused)? {
            return Ok(false);
        }
        if !self.failure_cleanup.supervised {
            if self.failure_cleanup.source.is_none() {
                self.failure_cleanup.source = Some(
                    policy
                        .authenticate_failed_supervision(
                            original,
                            target,
                            self.blobs.as_ref(),
                            self.refs.as_ref(),
                        )
                        .map_err(refused)?,
                );
            }
            policy
                .supervise_failed_original(
                    target,
                    self.failure_cleanup
                        .source
                        .as_mut()
                        .ok_or_else(|| refused("original qualified failure source absent"))?,
                )
                .map_err(refused)?;
            self.failure_cleanup.supervised = true;
        }
        if self.failure_cleanup.released.is_none() {
            let reopened = policy
                .authenticate_failed_supervision(
                    original,
                    target,
                    self.blobs.as_ref(),
                    self.refs.as_ref(),
                )
                .map_err(refused)?;
            let Some(records) = policy
                .failed_retirement_records(target, &reopened)
                .map_err(refused)?
            else {
                return Ok(false);
            };
            original
                .retain_terminal_failure(records, self.blobs.as_ref(), self.refs.as_ref())
                .map_err(refused)?;
            let summary = original.failure_summary().map_err(refused)?;
            if self.failure_cleanup.sealed.is_none() {
                self.failure_cleanup.sealed = Some(
                    self.ledger.seal_failed_retirement(
                        &self.reservation,
                        self.sealed
                            .as_ref()
                            .ok_or_else(|| refused("original unchanged refusal absent"))?,
                        target,
                        &summary,
                        &self.authenticator,
                    )?,
                );
            }
            let sealed = self
                .failure_cleanup
                .sealed
                .as_ref()
                .ok_or_else(|| refused("original failed release seal absent"))?;
            self.ledger
                .place_failed_retirement(&self.reservation, sealed)?;
            original
                .authenticate_terminal_failure(self.blobs.as_ref(), self.refs.as_ref())
                .map_err(refused)?;
            self.ledger.authenticate_failed_release(
                &self.reservation,
                self.sealed
                    .as_ref()
                    .ok_or_else(|| refused("original unchanged refusal absent"))?,
                target,
                &summary,
                sealed,
                &self.authenticator,
            )?;
            self.failure_cleanup.released = Some(
                policy
                    .release_failed_supervised(target, &reopened)
                    .map_err(refused)?,
            );
        }

        // Keep the source, ledger and opaque safe-release witness borrowed while
        // the owning Option remains occupied through any final Err/unwind.
        let qualification = FailureRelease {
            original: self
                .failure_retirement
                .as_ref()
                .ok_or_else(|| refused("original failure holder absent"))?,
            native: self
                .failure_cleanup
                .released
                .as_ref()
                .ok_or_else(|| refused("actual native release absent"))?,
            ledger: &self.ledger,
            reservation: &self.reservation,
            completion: self
                .sealed
                .as_ref()
                .ok_or_else(|| refused("original unchanged refusal absent"))?,
            sealed: self
                .failure_cleanup
                .sealed
                .as_ref()
                .ok_or_else(|| refused("original failed release seal absent"))?,
            authenticator: &self.authenticator,
            blobs: self.blobs.as_ref(),
            refs: self.refs.as_ref(),
        };
        QuarantinedRuntime::release_after_authenticated_supervision(
            &mut self.failure_cleanup.original,
            activation,
            &qualification,
        )
        .map_err(refused)?;
        Ok(true)
    }
}

struct FailureRelease<'a> {
    original: &'a crate::node_observed_executor::factory::PreparedFailureRetirement,
    native: &'a crate::node_observed_executor::factory::OriginalFailedNativeRelease,
    ledger: &'a super::super::super::ledger::CapabilityPreparationLedger,
    reservation: &'a super::super::super::ledger::CapabilityReservation,
    completion: &'a super::super::super::ledger::SealedCompletion,
    sealed: &'a super::super::super::ledger::failed_retirement::SealedFailedRetirement,
    authenticator: &'a super::super::retirement_auth::Authenticator,
    blobs: &'a dyn crucible_cas::content_store::ImmutableBlobBackend,
    refs: &'a dyn crucible_cas::content_store::MutableRefBackend,
}

impl GracefulRetirementQualification for FailureRelease<'_> {
    fn authenticate_release(
        &self,
        original: &QuarantinedRuntime,
        activation: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        if original.shutdown_failure().is_some() || original.remaining_owners() != 0 {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.original
            .authenticate_terminal_failure(self.blobs, self.refs)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let summary = self
            .original
            .failure_summary()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if !self.native.authenticates(activation.record(), &summary) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.ledger
            .authenticate_failed_release(
                self.reservation,
                self.completion,
                activation.record(),
                &summary,
                self.sealed,
                self.authenticator,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)
    }
}

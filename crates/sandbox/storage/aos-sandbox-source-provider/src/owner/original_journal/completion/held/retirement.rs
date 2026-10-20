//! Resident nonpositive preparation after genuine original Pending delivery.
//!
//! Only the same admitted Release child installs this reservoir. Its original
//! signed request, Pending bytes, Session, physical owners and native append
//! remain in that parent; no clone or stored borrow creates another owner.
//! Successful comparison waits for a genuinely current cleanup admission. It
//! cannot supply a census, floor, signature, export closure or release permit.

use super::super::OriginalProducerErrorV5;
use crate::ProviderLedgerError;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CleanupPreparationStageV1 {
    NativeComparison,
    AwaitCurrentAdmission,
    Closed,
}

#[derive(Clone, Copy)]
enum CleanupPreparationFailureV1 {
    Native,
    OwnerPost,
    ClockPost,
}

pub(super) struct OriginalSourceCleanupPreparationV1 {
    stage: CleanupPreparationStageV1,
    attempted: bool,
    native: Option<Result<(), OriginalProducerErrorV5>>,
    owner_post: Option<Result<(), OriginalProducerErrorV5>>,
    clock_post: Option<Result<(), ProviderLedgerError>>,
    first: Option<CleanupPreparationFailureV1>,
}

impl OriginalSourceCleanupPreparationV1 {
    pub(super) fn pending() -> Self {
        Self {
            stage: CleanupPreparationStageV1::NativeComparison,
            attempted: false,
            native: None,
            owner_post: None,
            clock_post: None,
            first: None,
        }
    }

    pub(super) fn awaiting_current_admission(&self) -> bool {
        self.stage == CleanupPreparationStageV1::AwaitCurrentAdmission
    }

    pub(super) fn begin_native_comparison(&mut self) -> bool {
        if self.attempted
            || self.first.is_some()
            || self.stage != CleanupPreparationStageV1::NativeComparison
            || self.native.is_some()
            || self.owner_post.is_some()
            || self.clock_post.is_some()
        {
            self.stage = CleanupPreparationStageV1::Closed;
            return false;
        }
        self.attempted = true;
        true
    }

    pub(super) fn park_native_comparison(&mut self, returned: Result<(), OriginalProducerErrorV5>) {
        if self.native.is_some() {
            std::process::abort();
        }
        if returned.is_err() {
            self.first.get_or_insert(CleanupPreparationFailureV1::Native);
        }
        self.native = Some(returned);
    }

    pub(super) fn park_owner_post(&mut self, returned: Result<(), OriginalProducerErrorV5>) {
        if self.owner_post.is_some() {
            std::process::abort();
        }
        if returned.is_err() {
            self.first.get_or_insert(CleanupPreparationFailureV1::OwnerPost);
        }
        self.owner_post = Some(returned);
    }

    pub(super) fn park_clock_post(&mut self, returned: Result<(), ProviderLedgerError>) {
        if self.clock_post.is_some() {
            std::process::abort();
        }
        if returned.is_err() {
            self.first.get_or_insert(CleanupPreparationFailureV1::ClockPost);
        }
        self.clock_post = Some(returned);
    }

    pub(super) fn finish_preparation(&mut self) -> bool {
        if self.first.is_none()
            && matches!(self.native, Some(Ok(())))
            && matches!(self.owner_post, Some(Ok(())))
            && matches!(self.clock_post, Some(Ok(())))
        {
            self.stage = CleanupPreparationStageV1::AwaitCurrentAdmission;
            true
        } else {
            self.stage = CleanupPreparationStageV1::Closed;
            false
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            CleanupPreparationFailureV1::Native => self.native.as_ref()?.as_ref().err()
                .map(|cause| cause as _),
            CleanupPreparationFailureV1::OwnerPost => self.owner_post.as_ref()?.as_ref().err()
                .map(|cause| cause as _),
            CleanupPreparationFailureV1::ClockPost => self.clock_post.as_ref()?.as_ref().err()
                .map(|cause| cause as _),
        }
    }

    pub(super) fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.owner_post.as_ref().and_then(|returned| returned.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| {
                self.clock_post.as_ref().and_then(|returned| returned.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}

//! Captures Root's fixed Storage verification manifest for metadata finality.
//!
//! The actual files and their independently owed recheck stay owned through the
//! final comparison. This owner supplies public verification DATA only; it has
//! no broker signing key, ownership lease, plan issuer or native CAS authority.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::RootFinalityRecoverStageReceivingV1;
use crate::policy_compiler::provisioning_current::RootContinuationClockGateV1;
use crate::public_api_session::RootCurrentStorageManifestCustodyV1;

type Cause = Box<dyn Error>;

#[derive(Clone, Copy)]
enum ExternalFailure { Clock }

/// Holds the actual fixed verification files and their captured model.
pub(crate) struct CreateFinalityStorageTrustOriginalV1 {
    files: RootCurrentStorageManifestCustodyV1,
    entered: bool,
    captured: Option<Result<(), ()>>,
    manifest: Option<Result<BrokerSessionManifestV1, Cause>>,
    typed: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    body: Option<Result<(), Cause>>,
    posted: Option<Result<(), ()>>,
    external_failure: Option<ExternalFailure>,
}

impl CreateFinalityStorageTrustOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            files: RootCurrentStorageManifestCustodyV1::new(),
            entered: false,
            captured: None,
            manifest: None,
            typed: None,
            body: None,
            posted: None,
            external_failure: None,
        }
    }

    pub(crate) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let bytes = size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        RootCurrentStorageManifestCustodyV1::dominant_demand()
            .ok_or(JournalError::JournalTooLarge)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(JournalError::ReceivingAccounting)
    }

    /// Captures once only after the genuine purpose paid the fixed owner.
    pub(crate) fn observe_once_v1(
        &mut self,
        stage: &mut RootFinalityRecoverStageReceivingV1<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        if self.entered {
            return Err(JournalError::ProtectedBoundary);
        }
        self.entered = true;
        self.body = Some((|| {
            self.observe_clock_frontier_v1(clock)?;
            self.captured = Some(self.files.capture_once());
            if !matches!(self.captured, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            // The manifest codec has a fixed-width closed representation. Its
            // carrier lives inline in this already priced native owner.
            self.typed = Some(stage.admit_finality_recover_trust_typed_once_v1(
                RootContinuationDemandV1::from_demand_v1(ResourceVector::ZERO),
            ));
            if !matches!(self.typed, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            self.observe_clock_frontier_v1(clock)?;
            let raw = self.files.bytes().ok_or(JournalError::ProtectedBoundary)?;
            self.manifest = Some(
                BrokerSessionManifestV1::decode(raw).map_err(|cause| Box::new(cause) as Cause),
            );
            if !matches!(self.manifest, Some(Ok(_))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(())
        })());
        self.manifest_v1().map(|_| ())
    }

    pub(crate) fn manifest_v1(&self) -> Result<&BrokerSessionManifestV1, JournalError> {
        if !matches!(self.body, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.manifest
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Runs the prearmed fixed-file post independently of body refusal.
    pub(crate) fn finish_posts_once_v1(&mut self) {
        if self.captured.is_some() && self.posted.is_none() {
            self.posted = Some(self.files.recheck_once());
        }
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        self.manifest_v1()?;
        if matches!(self.posted, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        // The actual clock is retained by the enclosing owner. Suppress only
        // this marker/late file post when that external source failed first;
        // its real native/provenance error then remains the outer selection.
        if matches!(self.external_failure, Some(ExternalFailure::Clock)) { return None; }
        self.files
            .capture_failure()
            .map(|cause| cause as _)
            .or_else(|| self.typed.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.manifest.as_ref()?.as_ref().err().map(|cause| &**cause))
            .or_else(|| self.body.as_ref()?.as_ref().err().map(|cause| &**cause))
            .or_else(|| self.files.post_failure().map(|cause| cause as _))
    }

    pub(crate) fn typed_funding_failed_v1(&self) -> bool {
        matches!(self.typed, Some(Err(_)))
    }

    fn observe_clock_frontier_v1(&mut self, clock: &mut RootContinuationClockGateV1)
        -> Result<(), Cause> {
        match clock.check_next_once_v1() {
            Ok(_) => Ok(()),
            Err(cause) => {
                self.external_failure = Some(ExternalFailure::Clock);
                Err(Box::new(cause))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::RetainedControllerProtectedClockAttemptV1;
    use crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1;

    #[test]
    fn actual_external_provenance_cause_precedes_later_trust_post_marker() {
        let mut original = RetainedControllerProtectedClockAttemptV1::default();
        let sample = original.observe_once_v1().unwrap();
        let horizon = RootContinuationHorizonDataV1::from_original_data_v1(sample,
            sample.boottime_nanoseconds().checked_add(65_000_000_000).unwrap()).unwrap();
        // The genuine kernel and protected CLI samplers retain different labels.
        // This deliberately mismatched input must retain the actual comparison.
        let mut clock = RootContinuationClockGateV1::new(horizon);
        let mut trust = CreateFinalityStorageTrustOriginalV1::new();
        trust.body = Some(trust.observe_clock_frontier_v1(&mut clock));
        let selected = clock.failure().unwrap() as *const (dyn Error + 'static);

        trust.posted = Some(Err(()));

        assert!(trust.failure().is_none());
        assert!(std::ptr::eq(selected, clock.failure().unwrap()));
        assert!(trust.require_complete_v1().is_err());
    }
}

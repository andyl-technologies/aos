//! Retains the actual adjacent Host Inventory attestation for healthy Stop.
//!
//! The same canonical challenge/effect/outcome codec and protected endpoint
//! signer serve ordinary and selected callers. These destinations preserve all
//! reached native checks and independently owed afters; they issue no grant.

use crate::{BrokerSessionSecurityError, endpoint::RetainedEndpointRevalidationOriginalV1};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox::lifecycle::{LifecycleEffectObservationV1, LifecyclePhase6ErrorV1};

#[derive(Default)]
pub(crate) struct StopAttestationCheckV5 {
    pub(crate) terminal: Option<Result<(), BrokerSessionSecurityError>>,
    pub(crate) endpoint_native: RetainedEndpointRevalidationOriginalV1,
    pub(crate) endpoint: Option<Result<(), BrokerSessionSecurityError>>,
    pub(crate) floor: Option<Result<(), BrokerSessionSecurityError>>,
}

impl StopAttestationCheckV5 {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.terminal).or_else(|| self.endpoint_native.failure())
            .or_else(|| error(&self.endpoint)).or_else(|| error(&self.floor))
    }
}

#[derive(Default)]
pub(crate) struct StopAttestationSignatureV5 {
    pub(crate) before_native: RetainedEndpointRevalidationOriginalV1,
    pub(crate) before: Option<Result<(), BrokerSessionSecurityError>>,
    pub(crate) signed: Option<Result<[u8; 64], BrokerSessionSecurityError>>,
    pub(crate) after_native: RetainedEndpointRevalidationOriginalV1,
    pub(crate) after: Option<Result<(), BrokerSessionSecurityError>>,
    pub(crate) closed: Option<BrokerSessionSecurityError>,
}

impl StopAttestationSignatureV5 {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before_native.failure().or_else(|| error(&self.before))
            .or_else(|| error(&self.signed)).or_else(|| self.after_native.failure())
            .or_else(|| error(&self.after)).or_else(|| self.closed.as_ref().map(|e| e as _))
    }
}

/// Owns the actual healthy Stop Inventory attestation and all entered checks.
#[derive(Default)]
#[must_use]
pub struct HostStopInventoryAttestationOriginalV5 {
    pub(crate) entered: bool,
    pub(crate) current: Option<Result<(), BrokerSessionSecurityError>>,
    pub(crate) message: Option<Result<[u8; 32], LifecyclePhase6ErrorV1>>,
    pub(crate) before: StopAttestationCheckV5,
    pub(crate) signature: StopAttestationSignatureV5,
    pub(crate) observation: Option<Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1>>,
    pub(crate) after: StopAttestationCheckV5,
    pub(crate) closed: Option<BrokerSessionSecurityError>,
}

impl HostStopInventoryAttestationOriginalV5 {
    /// Describes every additional native check before its first entry.
    #[must_use]
    pub fn receiving_demand_v5() -> Option<ResourceVector> {
        let header = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(std::mem::size_of::<Self>().checked_mul(2)?).ok()?);
        let endpoint = RetainedEndpointRevalidationOriginalV1::receiving_demand_v1()?;
        header.checked_add(endpoint).ok()?.checked_add(endpoint).ok()?
            .checked_add(endpoint).ok()?.checked_add(endpoint).ok()
    }

    /// Borrows the exact external native post cause at its original frontier.
    ///
    /// The owned marker remains here, while the same interval's post owns its
    /// native/parser prefix. Selection follows the reached phase immediately;
    /// a later independent post cannot replace an earlier message or signer error.
    #[must_use]
    pub fn failure_with_post_v5<'owner>(&'owner self, post: &'owner crate::ExecutionClientPostOriginalV1)
        -> Option<&'owner (dyn std::error::Error + 'static)> {
        if matches!(self.current, Some(Err(_))) {
            return post.terminal_before_failure_v1().or_else(|| error(&self.current));
        }
        if let Some(cause) = phase_error(&self.message) { return Some(cause); }
        if matches!(self.before.terminal, Some(Err(_))) {
            return post.terminal_before_failure_v1().or_else(|| error(&self.before.terminal));
        }
        if let Some(cause) = self.before.failure() { return Some(cause); }
        if let Some(cause) = self.signature.failure() { return Some(cause); }
        if let Some(cause) = phase_error(&self.observation) { return Some(cause); }
        if matches!(self.after.terminal, Some(Err(_))) {
            return post.terminal_after_failure_v1().or_else(|| error(&self.after.terminal));
        }
        self.after.failure().or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Borrows the earliest retained attestation cause without reconstruction.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.current).or_else(|| phase_error(&self.message))
            .or_else(|| self.before.failure()).or_else(|| self.signature.failure())
            .or_else(|| phase_error(&self.observation)).or_else(|| self.after.failure())
            .or_else(|| self.closed.as_ref().map(|e| e as _))
    }
}

fn error<T>(value: &Option<Result<T, BrokerSessionSecurityError>>) -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn phase_error<T>(value: &Option<Result<T, LifecyclePhase6ErrorV1>>) -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

//! Non-production fixed-root composition for the dormant runtime backend.
//!
//! This module proves that the RFC-0021 backend can be constructed from its
//! protected owner and can expose the probe evidence that justified the
//! composition. It opens no listener, registers no route, starts no Host
//! service, and never publishes service readiness.

use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionOwnerErrorV1, DormantRuntimeExecutionOwnerV1,
};
use aos_sandbox_core::runtime_backend::RuntimeBackendError;

use super::{DormantProtectedRuntimeBackendV1, DormantRuntimeBackendReadinessEvidenceV1};

/// Owns fixed-root runtime state without activating the Host service.
pub struct DormantRuntimeBackendCompositionV1 {
    owner: DormantRuntimeExecutionOwnerV1,
}

impl DormantRuntimeBackendCompositionV1 {
    /// Performs one dormant fixed-manifest bootstrap without activating Host.
    ///
    /// The protected manifest path, fs-verity measurement sidecar, keys,
    /// capabilities, and runtime plan are fixed inside the owner boundary. No
    /// caller-selected provisioning value or retry capability crosses this API.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeBackendCompositionErrorV1`] when protected
    /// manifest authentication, one-shot provisioning, or exact recovery fails.
    #[cfg(target_os = "linux")]
    pub fn bootstrap_fixed() -> Result<Self, DormantRuntimeBackendCompositionErrorV1> {
        Ok(Self {
            owner: DormantRuntimeExecutionOwnerV1::bootstrap_fixed()?,
        })
    }

    /// Opens the dormant fixed-root owner without constructing a listener.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeBackendCompositionErrorV1`] when protected
    /// fixed-root journal opening or replay fails.
    pub fn open() -> Result<Self, DormantRuntimeBackendCompositionErrorV1> {
        Ok(Self {
            owner: DormantRuntimeExecutionOwnerV1::open()?,
        })
    }

    /// Claims and constructs one dormant backend with protected probe evidence.
    ///
    /// The returned composition borrows the owner exclusively for the complete
    /// backend lifetime. Its readiness evidence is local diagnostic evidence,
    /// not permission to advertise Host readiness or accept traffic.
    ///
    /// # Errors
    ///
    /// Returns [`DormantRuntimeBackendCompositionErrorV1`] when the fixed-root
    /// claim or backend evidence is absent, stale, malformed, or inconsistent.
    pub fn compose(
        &mut self,
    ) -> Result<DormantComposedRuntimeBackendV1<'_>, DormantRuntimeBackendCompositionErrorV1> {
        let claim = self.owner.claim()?;
        let backend = DormantProtectedRuntimeBackendV1::from_protected_claim(claim)?;
        let readiness_evidence = backend.readiness_evidence()?;
        Ok(DormantComposedRuntimeBackendV1 {
            backend,
            readiness_evidence,
        })
    }
}

/// Retains a dormant backend beside the exact evidence used to construct it.
pub struct DormantComposedRuntimeBackendV1<'owner> {
    backend: DormantProtectedRuntimeBackendV1<'owner>,
    readiness_evidence: DormantRuntimeBackendReadinessEvidenceV1,
}

impl<'owner> DormantComposedRuntimeBackendV1<'owner> {
    /// Borrows nonadvertised protected readiness evidence.
    #[must_use]
    pub const fn readiness_evidence(&self) -> &DormantRuntimeBackendReadinessEvidenceV1 {
        &self.readiness_evidence
    }

    /// Borrows the constructed dormant backend.
    #[must_use]
    pub const fn backend(&self) -> &DormantProtectedRuntimeBackendV1<'owner> {
        &self.backend
    }

    /// Mutably borrows the constructed dormant backend.
    #[must_use]
    pub fn backend_mut(&mut self) -> &mut DormantProtectedRuntimeBackendV1<'owner> {
        &mut self.backend
    }
}

/// Reports fixed-root dormant composition failure.
#[derive(Debug, thiserror::Error)]
pub enum DormantRuntimeBackendCompositionErrorV1 {
    /// Protected owner opening, claim, or replay failed.
    #[error("dormant runtime owner composition failed: {0}")]
    Owner(#[from] DormantRuntimeExecutionOwnerErrorV1),
    /// Backend construction rejected protected readiness evidence.
    #[error("dormant runtime backend composition failed: {0}")]
    Backend(#[from] RuntimeBackendError),
}

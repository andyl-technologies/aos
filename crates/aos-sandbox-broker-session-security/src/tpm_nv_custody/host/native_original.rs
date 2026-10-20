//! Borrows only actual Canary-request or normal Source native originals.
//!
//! Both branches enter the same physical/sidecar/main engines. The enum is
//! private to this custody implementation; no bytes, descriptor, declared mode,
//! scalar clock, preimage callback or external trait can construct its variants.

use aos_sandbox::{
    RuntimeBootPreparationNativeOriginalV1, RuntimeDeploymentOriginalClockCauseV3,
    RuntimeDeploymentOriginalWindowV3,
};

#[derive(Clone, Copy)]
pub(in crate::tpm_nv_custody) enum PublisherNativeOriginalRefV3<'a, 'origin, 'startup> {
    Canary(&'a RuntimeDeploymentOriginalWindowV3),
    Boot(&'a RuntimeBootPreparationNativeOriginalV1<'origin, 'startup>),
}

impl PublisherNativeOriginalRefV3<'_, '_, '_> {
    pub(in crate::tpm_nv_custody) fn begin_outer_startup_after_v1(
        &self,
    ) -> Result<(), aos_sandbox::RuntimeDeploymentComparisonErrorV1> {
        match self {
            Self::Canary(_) => Ok(()),
            Self::Boot(original) => original.begin_outer_startup_after_v1(),
        }
    }

    pub(in crate::tpm_nv_custody) fn finish_outer_startup_after_owed_once_v1(
        &self,
    ) -> Result<(), RuntimeDeploymentOriginalClockCauseV3> {
        match self {
            Self::Canary(_) => Ok(()),
            Self::Boot(original) => original.finish_outer_startup_after_owed_once_v1(),
        }
    }

    pub(in crate::tpm_nv_custody) fn require_clock(
        &self,
    ) -> Result<(), RuntimeDeploymentOriginalClockCauseV3> {
        match self {
            Self::Canary(original) => original.require_clock(),
            Self::Boot(original) => original.require_clock(),
        }
    }

    pub(in crate::tpm_nv_custody) fn require_owed_clock(
        &self,
    ) -> Result<(), RuntimeDeploymentOriginalClockCauseV3> {
        match self {
            Self::Canary(original) => original.require_clock(),
            Self::Boot(original) => original.require_clock_owed_once_v1(),
        }
    }
}

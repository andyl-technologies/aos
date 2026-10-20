//! Borrows only the two genuine captured publisher startup owners.
//!
//! The closed reference keeps common055 mechanics independent of the initial
//! table recipe. Neither variant can be constructed from a descriptor, profile,
//! record, digest, resource vector or caller assertion of currentness.

use aos_sandbox_linux::pidfd::PidFd;
use sha2::{Digest as _, Sha256};

use crate::immutable_image::RetainedImmutableFileV1;
use crate::tpm_nv_custody::NvCustodyErrorV1;

use super::invocation::HostPhysicalInvocationStateV1;
use super::{
    ProductionRuntimeDeploymentStartupV1, RuntimeBootPreparationStartupOriginalV1,
    RuntimeDeploymentComparisonErrorV1,
};

#[derive(Clone, Copy)]
pub(super) enum PublisherStartupOriginalRefV3<'startup> {
    Existing(&'startup ProductionRuntimeDeploymentStartupV1),
    Boot(&'startup RuntimeBootPreparationStartupOriginalV1),
}

impl<'startup> PublisherStartupOriginalRefV3<'startup> {
    pub(super) fn recheck(self) -> Result<(), NvCustodyErrorV1> {
        match self {
            Self::Existing(startup) => startup
                .recheck()
                .map_err(|_| NvCustodyErrorV1::Provisioning),
            Self::Boot(startup) => startup
                .require_current_v1()
                .map_err(|_| NvCustodyErrorV1::Provisioning),
        }
    }

    pub(super) fn recheck_comparison(self) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        match self {
            Self::Existing(startup) => startup.recheck().map_err(Into::into),
            Self::Boot(startup) => startup.require_current_v1().map_err(Into::into),
        }
    }

    pub(super) fn existing(self) -> Option<&'startup ProductionRuntimeDeploymentStartupV1> {
        match self {
            Self::Existing(startup) => Some(startup),
            Self::Boot(_) => None,
        }
    }

    pub(super) fn boot(self) -> Option<&'startup RuntimeBootPreparationStartupOriginalV1> {
        match self {
            Self::Boot(startup) => Some(startup),
            Self::Existing(_) => None,
        }
    }

    pub(super) fn profile_digest(self) -> Result<[u8; 32], NvCustodyErrorV1> {
        match self {
            Self::Existing(startup) => Ok(startup.profile_digest()),
            Self::Boot(startup) => Ok(Sha256::digest(
                startup
                    .profile_bytes_v1()
                    .map_err(|_| NvCustodyErrorV1::Provisioning)?,
            )
            .into()),
        }
    }

    pub(super) fn canonical_policy_digest(self) -> Result<[u8; 32], NvCustodyErrorV1> {
        match self {
            Self::Existing(startup) => Ok(startup.canonical_policy_digest()),
            Self::Boot(startup) => Ok(startup
                .profile_data_v1()
                .map_err(|_| NvCustodyErrorV1::Provisioning)?
                .publisher
                .canonical_policy
                .sha256),
        }
    }

    pub(super) fn physical_invocation_state(self) -> &'startup HostPhysicalInvocationStateV1 {
        match self {
            Self::Existing(startup) => startup.host_physical_invocation_state(),
            Self::Boot(startup) => startup.physical_invocation_state_v1(),
        }
    }

    pub(super) fn retained_pid1(
        self,
    ) -> Result<&'startup RetainedImmutableFileV1, NvCustodyErrorV1> {
        match self {
            Self::Existing(startup) => Ok(startup.retained_pid1()),
            Self::Boot(startup) => startup
                .retained_pid1_v1()
                .map_err(|_| NvCustodyErrorV1::Provisioning),
        }
    }

    pub(super) fn require_child(
        self,
        child: &PidFd,
    ) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        match self {
            Self::Existing(startup) => startup.require_child(child).map_err(Into::into),
            Self::Boot(startup) => startup.require_child_v1(child).map_err(Into::into),
        }
    }
}

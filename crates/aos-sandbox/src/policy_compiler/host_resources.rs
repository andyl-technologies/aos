//! Normalizes Host resource DATA through the same actual systemd numeric fold.
//!
//! This owns no Root admission, policy compiler or signing key. Its caller
//! retains the fresh candidate, verifies the full policy and every other role's
//! resource obligations, and admits this bounded representation before entry.

use aos_proto::aos::sandbox::local::v1::{Feature, ResourceLimit};
use aos_sandbox_core::model::ResourceProfile;
use aos_sandbox_protocol::host_resource_projection::{
    HostPortableResourceProjectionV1, HostResourceProjectionErrorV1,
    HOST_IMPLEMENTED_FEATURES_V1,
};
use aos_systemd::{SandboxResourceRecipeV1, SandboxResourceRecipeErrorV1, SandboxResources};

#[derive(Debug, thiserror::Error)]
pub(crate) enum HostResourceNormalizationErrorV1 {
    #[error(transparent)]
    Projection(#[from] HostResourceProjectionErrorV1),
    #[error(transparent)]
    Resources(#[from] SandboxResourceRecipeErrorV1),
}

/// Keeps the original portable profile beside the same compiled numeric DATA.
pub(crate) struct NormalizedHostResourceInputsV1<'profile> {
    projection: HostPortableResourceProjectionV1<'profile>,
    _resources: SandboxResources,
}

impl<'profile> NormalizedHostResourceInputsV1<'profile> {
    pub(crate) fn from_profile_v1(profile: &'profile ResourceProfile)
        -> Result<Self, HostResourceNormalizationErrorV1>
    {
        let projection = HostPortableResourceProjectionV1::from_profile_v1(profile)?;
        let values = projection.values_v1();
        let resources = SandboxResourceRecipeV1 {
            memory_max_bytes: values.memory_max_bytes,
            tasks_max: values.tasks_max,
            cpu_weight: values.cpu_weight,
            open_files: values.open_files,
            cpu_quota_micros_per_second: values.cpu_quota_micros_per_second,
            io_weight: values.io_weight,
        }.compile_v1()?;
        Ok(Self { projection, _resources: resources })
    }

    pub(crate) fn wire_limits_v1(&self) -> Vec<ResourceLimit> {
        self.projection.wire_limits_v1()
    }

    pub(crate) fn wire_features_v1(&self) -> Vec<Feature> {
        self.projection.wire_features_v1()
    }

    // Fixed six limit rows grow through at most an eight-cell backing;
    // four exact feature rows and their actual namespace strings coexist with
    // the unchanged candidate. No full-profile copy or field Meta fee occurs.
    pub(crate) fn receiving_bytes_v1() -> Option<usize> {
        let strings = HOST_IMPLEMENTED_FEATURES_V1.iter()
            .try_fold(0usize, |bytes, (namespace, _, _)| bytes.checked_add(namespace.len()))?;
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(SandboxResourceRecipeV1::compilation_receiving_bytes_v1()?)?
            .checked_add(std::mem::size_of::<ResourceLimit>().checked_mul(8)?.checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Feature>().checked_mul(4)?.checked_mul(3)?)?
            .checked_add(strings.checked_mul(3)?)
    }
}

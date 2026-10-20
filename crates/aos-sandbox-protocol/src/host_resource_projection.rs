//! Projects the exact portable policy registry onto implemented Host properties.
//!
//! This is comparison and encoding DATA, never a Root admission or Host grant.
//! The full borrowed source profile remains available: Storage, Cache, Mount,
//! FUSE and broker-enforced dimensions require their own actual owners. A finite
//! I/O-bandwidth request is refused because this Host recipe has no I/O-max
//! provider. The sixteen portable dimensions are never accounting dimensions.

use aos_proto::aos::sandbox::local::v1::{Feature, ResourceLimit};
use aos_sandbox_core::model::{LimitDimension, LimitValue, ResourceProfile};

/// Lists the exact registered feature versions implemented by the Host backend.
pub const HOST_IMPLEMENTED_FEATURES_V1: &[(&str, u32, u32)] = &[
    ("aos.sandbox.runtime.linux-systemd", 1, 0),
    ("aos.sandbox.identity.posix32", 1, 0),
    ("aos.sandbox.enforcement.cgroup-v2", 1, 0),
    ("aos.sandbox.enforcement.broker-ledger", 1, 0),
];

/// Carries the finite numeric inputs consumed by the shared systemd recipe.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostResourceLimitValuesDataV1 {
    /// The hard payload memory limit in bytes.
    pub memory_max_bytes: Option<u64>,
    /// The payload process/task limit.
    pub tasks_max: Option<u64>,
    /// The relative CPU weight.
    pub cpu_weight: Option<u64>,
    /// The open-file descriptor limit.
    pub open_files: Option<u64>,
    /// The optional allowed CPU runtime per second in microseconds.
    pub cpu_quota_micros_per_second: Option<u64>,
    /// The optional relative block-I/O weight.
    pub io_weight: Option<u64>,
}

/// Refuses a portable limit that the Host projection cannot represent honestly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HostResourceProjectionErrorV1 {
    /// No actual I/O bandwidth enforcement provider exists in this recipe.
    #[error("the Host recipe cannot enforce finite I/O bandwidth")]
    IoBandwidth,
    /// A Host-local value is inherited or unlimited instead of finite.
    #[error("the Host recipe requires a finite {0:?} limit")]
    NotFinite(LimitDimension),
    /// The exact Host-local enforcement profile/version does not match.
    #[error("the Host recipe cannot enforce {0:?} with this profile")]
    Enforcement(LimitDimension),
}

/// Borrows the complete original profile beside its six-property projection.
#[derive(Clone, Copy)]
pub struct HostPortableResourceProjectionV1<'profile> {
    original: &'profile ResourceProfile,
    values: HostResourceLimitValuesDataV1,
}

impl<'profile> HostPortableResourceProjectionV1<'profile> {
    /// Projects implemented Host properties without parsing or allocating.
    ///
    /// The caller must additionally run the same systemd numeric recipe before
    /// signing a template and independently enforce every non-Host dimension.
    /// In particular, this does not discard or settle the original Storage
    /// quota/reservation, Cache, mount, FUSE or broker-ledger obligations.
    ///
    /// # Errors
    /// Refuses finite I/O bandwidth, nonfinite Host-local limits or a different
    /// Host enforcement feature/version. It authenticates no policy provenance.
    pub fn from_profile_v1(original: &'profile ResourceProfile)
        -> Result<Self, HostResourceProjectionErrorV1>
    {
        let mut values = HostResourceLimitValuesDataV1::default();
        for limit in original.limits() {
            let dimension = limit.dimension();
            if dimension == LimitDimension::IoBandwidth {
                if matches!(limit.value(), LimitValue::Bounded(_)) {
                    return Err(HostResourceProjectionErrorV1::IoBandwidth);
                }
                continue;
            }
            let destination = match dimension {
                LimitDimension::Memory => &mut values.memory_max_bytes,
                LimitDimension::Processes => &mut values.tasks_max,
                LimitDimension::CpuWeight => &mut values.cpu_weight,
                LimitDimension::CpuQuota => &mut values.cpu_quota_micros_per_second,
                LimitDimension::IoWeight => &mut values.io_weight,
                LimitDimension::OpenFiles => &mut values.open_files,
                _ => continue,
            };
            let expected = if dimension == LimitDimension::OpenFiles {
                "aos.sandbox.enforcement.broker-ledger"
            } else {
                "aos.sandbox.enforcement.cgroup-v2"
            };
            let enforcement = limit.enforcement();
            if enforcement.namespace() != expected || enforcement.major() != 1 || enforcement.minor() != 0 {
                return Err(HostResourceProjectionErrorV1::Enforcement(dimension));
            }
            let LimitValue::Bounded(value) = limit.value() else {
                return Err(HostResourceProjectionErrorV1::NotFinite(dimension));
            };
            *destination = Some(value);
        }
        Ok(Self { original, values })
    }

    /// Borrows the unchanged full profile, including all non-Host obligations.
    #[must_use]
    pub const fn original_profile_v1(&self) -> &'profile ResourceProfile { self.original }

    /// Returns only the exact six numeric inputs for the shared systemd recipe.
    #[must_use]
    pub const fn values_v1(&self) -> HostResourceLimitValuesDataV1 { self.values }

    /// Encodes the six represented finite limits in canonical dimension order.
    ///
    /// This allocates at most six inert wire rows. Receiving must precede entry;
    /// the result neither creates a live request nor proves implementation.
    #[must_use]
    pub fn wire_limits_v1(&self) -> Vec<ResourceLimit> {
        let values = self.values;
        [
            (LimitDimension::Processes, values.tasks_max),
            (LimitDimension::Memory, values.memory_max_bytes),
            (LimitDimension::CpuWeight, values.cpu_weight),
            (LimitDimension::CpuQuota, values.cpu_quota_micros_per_second),
            (LimitDimension::IoWeight, values.io_weight),
            (LimitDimension::OpenFiles, values.open_files),
        ].into_iter().filter_map(|(dimension, value)| value.map(|value| ResourceLimit {
            dimension: u32::from(dimension as u8), value, ..Default::default()
        })).collect()
    }

    /// Encodes this fixed backend's required features in canonical name order.
    ///
    /// Other roles' required features remain on the original full policy and
    /// require their own actual enforcement. This is no capability assertion.
    #[must_use]
    pub fn wire_features_v1(&self) -> Vec<Feature> {
        let mut features: Vec<_> = HOST_IMPLEMENTED_FEATURES_V1.iter()
            .map(|(namespace, major, minor)| Feature {
                namespace: (*namespace).to_owned(), major: *major, minor: *minor,
                ..Default::default()
            }).collect();
        features.sort_by(|left, right| left.namespace.cmp(&right.namespace));
        features
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{FeatureRef, model::Limit};

    #[test]
    fn real_portable_dimension_seven_refuses_instead_of_becoming_an_accounting_field() {
        let profile = ResourceProfile::new(vec![Limit::new(LimitDimension::IoBandwidth,
            LimitValue::Bounded(1), FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0).unwrap())]).unwrap();

        assert!(matches!(HostPortableResourceProjectionV1::from_profile_v1(&profile),
            Err(HostResourceProjectionErrorV1::IoBandwidth)));
    }

    #[test]
    fn host_projection_retains_original_storage_quota_and_uses_true_process_dimension_two() {
        let profile = ResourceProfile::new(vec![
            Limit::new(LimitDimension::Bytes, LimitValue::Bounded(4096),
                FeatureRef::new("aos.sandbox.enforcement.zfs-quota", 1, 0).unwrap()),
            Limit::new(LimitDimension::Processes, LimitValue::Bounded(3),
                FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0).unwrap()),
        ]).unwrap();

        let projection = HostPortableResourceProjectionV1::from_profile_v1(&profile).unwrap();
        let wire = projection.wire_limits_v1();

        assert!(std::ptr::eq(projection.original_profile_v1(), &profile));
        assert_eq!(projection.original_profile_v1().limits()[0].dimension(), LimitDimension::Bytes);
        assert_eq!(wire.len(), 1);
        assert_eq!((wire[0].dimension, wire[0].value), (2, 3));
    }
}

//! Portable sandbox specification and closed profile values.
//!
//! A specification commits to logical runtime, identity, resource,
//! environment, view, attachment-slot, and network requirements. Placement,
//! host paths, runtime process IDs, credentials, and backend observations are
//! intentionally absent.

use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use crate::{AttachmentSlotId, FeatureRef, GrantId, NetworkEndpointId, ObjectDescriptor};

/// Reports an invalid sandbox specification value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidSpecModel {
    /// A set-valued collection is not strictly ordered and unique.
    #[error("set-valued collection must be strictly ordered and unique")]
    SetNotCanonical,
    /// Resource limits repeat or reorder a closed dimension.
    #[error("resource limits must be strictly ordered by closed dimension")]
    LimitsNotCanonical,
    /// A network kind has an invalid endpoint collection.
    #[error("network endpoint requirements are incompatible with the network kind")]
    InvalidNetworkEndpoints,
}

/// Selects the treatment of metadata identities outside an allocated userns range.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnmappableIdentityPolicy {
    /// Rejects the view or sandbox instead of changing an identity.
    Reject,
    /// Synthesizes identity only through a separately isolated presentation.
    IsolatedSynthesizedPresentation,
}

/// Selects one closed portable sandbox identity profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum IdentityProfile {
    /// Requires a private user namespace with a contiguous ID allocation.
    PrivateUserns {
        /// Positive number of guest-visible IDs required.
        id_range_size: NonZeroU32,
        /// Fail-closed handling for metadata outside the allocation.
        unmappable_policy: UnmappableIdentityPolicy,
        /// Exact semantic features required by this identity profile.
        required_features: Vec<FeatureRef>,
    },
    /// Exceptionally presents host identity without a private user namespace.
    Host {
        /// Exact semantic features required by exceptional host identity.
        required_features: Vec<FeatureRef>,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", deny_unknown_fields)]
enum IdentityProfileWire {
    PrivateUserns {
        id_range_size: NonZeroU32,
        unmappable_policy: UnmappableIdentityPolicy,
        required_features: Vec<FeatureRef>,
    },
    Host {
        required_features: Vec<FeatureRef>,
    },
}

impl<'de> Deserialize<'de> for IdentityProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let profile = match IdentityProfileWire::deserialize(deserializer)? {
            IdentityProfileWire::PrivateUserns {
                id_range_size,
                unmappable_policy,
                required_features,
            } => Self::PrivateUserns {
                id_range_size,
                unmappable_policy,
                required_features,
            },
            IdentityProfileWire::Host { required_features } => Self::Host { required_features },
        };
        profile.validate().map_err(serde::de::Error::custom)
    }
}

impl IdentityProfile {
    /// Validates that the profile's feature set is canonical.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSpecModel::SetNotCanonical`] for unordered or
    /// duplicate required features.
    pub fn validate(self) -> Result<Self, InvalidSpecModel> {
        let features = match &self {
            Self::PrivateUserns {
                required_features, ..
            }
            | Self::Host { required_features } => required_features,
        };
        validate_set(features)?;
        Ok(self)
    }

    /// Returns the exact required feature set.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        match self {
            Self::PrivateUserns {
                required_features, ..
            }
            | Self::Host { required_features } => required_features,
        }
    }
}

/// Identifies one closed v1 portable resource-limit dimension.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
#[serde(rename_all = "kebab-case")]
pub enum LimitDimension {
    /// Persistent or staged storage bytes.
    Bytes = 0,
    /// Persistent inode count.
    Inodes = 1,
    /// Payload process count.
    Processes = 2,
    /// Payload and charged-helper memory bytes.
    Memory = 3,
    /// Relative CPU scheduling weight.
    CpuWeight = 4,
    /// CPU quota under the runtime profile's period.
    CpuQuota = 5,
    /// Relative block-I/O scheduling weight.
    IoWeight = 6,
    /// Aggregate admitted block-I/O bandwidth.
    IoBandwidth = 7,
    /// Brokered and statically configured mount count.
    MountCount = 8,
    /// Aggregate open-file envelope.
    OpenFiles = 9,
    /// Concurrent admitted FUSE requests.
    FuseRequests = 10,
    /// FUSE worker and request memory bytes.
    FuseMemory = 11,
    /// Reserved cache bytes.
    CacheBytes = 12,
    /// Retained snapshot count.
    SnapshotCount = 13,
    /// Direct child sandbox count.
    ChildCount = 14,
    /// Concurrent execution count.
    ExecutionCount = 15,
}

/// Stores one explicit requested or resolved limit value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum LimitValue {
    /// Defers the value to a containing ceiling during request resolution.
    Inherited,
    /// Applies an explicit finite bound, including zero.
    Bounded(u64),
    /// Carries the grant that authorized an unbounded value.
    Unlimited(GrantId),
}

/// Stores one limit and the mechanism required to enforce it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limit {
    dimension: LimitDimension,
    value: LimitValue,
    enforcement: FeatureRef,
}

impl Limit {
    /// Constructs one typed portable resource limit.
    #[must_use]
    pub const fn new(
        dimension: LimitDimension,
        value: LimitValue,
        enforcement: FeatureRef,
    ) -> Self {
        Self {
            dimension,
            value,
            enforcement,
        }
    }

    /// Returns the closed resource dimension.
    #[must_use]
    pub const fn dimension(&self) -> LimitDimension {
        self.dimension
    }

    /// Returns the explicit limit value.
    #[must_use]
    pub const fn value(&self) -> LimitValue {
        self.value
    }

    /// Returns the required enforcement mechanism profile.
    #[must_use]
    pub const fn enforcement(&self) -> &FeatureRef {
        &self.enforcement
    }
}

/// Stores resource limits in strict closed-dimension order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ResourceProfile(Vec<Limit>);

impl ResourceProfile {
    /// Constructs a resource profile without duplicate dimensions.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSpecModel::LimitsNotCanonical`] unless dimensions are
    /// strictly increasing.
    pub fn new(limits: Vec<Limit>) -> Result<Self, InvalidSpecModel> {
        if limits
            .windows(2)
            .all(|pair| pair[0].dimension() < pair[1].dimension())
        {
            Ok(Self(limits))
        } else {
            Err(InvalidSpecModel::LimitsNotCanonical)
        }
    }

    /// Returns limits in stable dimension order.
    #[must_use]
    pub fn limits(&self) -> &[Limit] {
        &self.0
    }

    /// Reports whether unresolved inheritance remains in the profile.
    #[must_use]
    pub fn contains_inherited(&self) -> bool {
        self.0
            .iter()
            .any(|limit| limit.value() == LimitValue::Inherited)
    }
}

impl<'de> Deserialize<'de> for ResourceProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(Vec::<Limit>::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Selects one closed logical network exposure class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkKind {
    /// Provides only a private network namespace and loopback.
    Isolated,
    /// Connects to explicitly named project-local endpoints.
    Project,
    /// Permits explicitly named outbound endpoint policies.
    Outbound,
    /// Publishes explicitly named ingress endpoint policies.
    Published,
    /// Exceptionally shares the host network namespace.
    Host,
}

/// Stores a logical network profile without addresses or host interface names.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkProfile {
    kind: NetworkKind,
    endpoint_ids: Vec<NetworkEndpointId>,
    required_features: Vec<FeatureRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkProfileWire {
    kind: NetworkKind,
    endpoint_ids: Vec<NetworkEndpointId>,
    required_features: Vec<FeatureRef>,
}

impl<'de> Deserialize<'de> for NetworkProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = NetworkProfileWire::deserialize(deserializer)?;
        Self::new(wire.kind, wire.endpoint_ids, wire.required_features)
            .map_err(serde::de::Error::custom)
    }
}

impl NetworkProfile {
    /// Constructs a closed logical network profile.
    ///
    /// # Errors
    ///
    /// Returns an error unless endpoint and feature sets are canonical, or if
    /// isolated/host networking carries inapplicable endpoints.
    pub fn new(
        kind: NetworkKind,
        endpoint_ids: Vec<NetworkEndpointId>,
        required_features: Vec<FeatureRef>,
    ) -> Result<Self, InvalidSpecModel> {
        validate_set(&endpoint_ids)?;
        validate_set(&required_features)?;
        if matches!(kind, NetworkKind::Isolated | NetworkKind::Host) && !endpoint_ids.is_empty() {
            return Err(InvalidSpecModel::InvalidNetworkEndpoints);
        }
        Ok(Self {
            kind,
            endpoint_ids,
            required_features,
        })
    }

    /// Returns the closed network kind.
    #[must_use]
    pub const fn kind(&self) -> NetworkKind {
        self.kind
    }

    /// Returns logical endpoint identities in canonical order.
    #[must_use]
    pub fn endpoint_ids(&self) -> &[NetworkEndpointId] {
        &self.endpoint_ids
    }

    /// Returns the exact required feature set.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }
}

/// Stores one complete portable sandbox specification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SandboxSpec {
    runtime_profile: FeatureRef,
    identity_profile: IdentityProfile,
    resource_profile: ResourceProfile,
    environment: ObjectDescriptor,
    root_view: ObjectDescriptor,
    attachment_slots: Vec<AttachmentSlotId>,
    network_profile: NetworkProfile,
    required_features: Vec<FeatureRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxSpecWire {
    runtime_profile: FeatureRef,
    identity_profile: IdentityProfile,
    resource_profile: ResourceProfile,
    environment: ObjectDescriptor,
    root_view: ObjectDescriptor,
    attachment_slots: Vec<AttachmentSlotId>,
    network_profile: NetworkProfile,
    required_features: Vec<FeatureRef>,
}

impl<'de> Deserialize<'de> for SandboxSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SandboxSpecWire::deserialize(deserializer)?;
        Self::new(
            wire.runtime_profile,
            wire.identity_profile,
            wire.resource_profile,
            wire.environment,
            wire.root_view,
            wire.attachment_slots,
            wire.network_profile,
            wire.required_features,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl SandboxSpec {
    /// Constructs a complete portable sandbox specification.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid nested profiles or unordered attachment
    /// slots and required features.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime_profile: FeatureRef,
        identity_profile: IdentityProfile,
        resource_profile: ResourceProfile,
        environment: ObjectDescriptor,
        root_view: ObjectDescriptor,
        attachment_slots: Vec<AttachmentSlotId>,
        network_profile: NetworkProfile,
        required_features: Vec<FeatureRef>,
    ) -> Result<Self, InvalidSpecModel> {
        let identity_profile = identity_profile.validate()?;
        validate_set(&attachment_slots)?;
        validate_set(&required_features)?;
        Ok(Self {
            runtime_profile,
            identity_profile,
            resource_profile,
            environment,
            root_view,
            attachment_slots,
            network_profile,
            required_features,
        })
    }

    /// Returns the requested portable runtime profile.
    #[must_use]
    pub const fn runtime_profile(&self) -> &FeatureRef {
        &self.runtime_profile
    }

    /// Returns the closed identity profile.
    #[must_use]
    pub const fn identity_profile(&self) -> &IdentityProfile {
        &self.identity_profile
    }

    /// Returns the typed resource profile.
    #[must_use]
    pub const fn resource_profile(&self) -> &ResourceProfile {
        &self.resource_profile
    }

    /// Returns the immutable environment descriptor.
    #[must_use]
    pub const fn environment(&self) -> &ObjectDescriptor {
        &self.environment
    }

    /// Returns the root filesystem-view descriptor.
    #[must_use]
    pub const fn root_view(&self) -> &ObjectDescriptor {
        &self.root_view
    }

    /// Returns broker-owned destination slots in canonical identity order.
    #[must_use]
    pub fn attachment_slots(&self) -> &[AttachmentSlotId] {
        &self.attachment_slots
    }

    /// Returns the closed logical network profile.
    #[must_use]
    pub const fn network_profile(&self) -> &NetworkProfile {
        &self.network_profile
    }

    /// Returns the exact required feature set.
    #[must_use]
    pub fn required_features(&self) -> &[FeatureRef] {
        &self.required_features
    }
}

fn validate_set<T: Ord>(values: &[T]) -> Result<(), InvalidSpecModel> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(InvalidSpecModel::SetNotCanonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MediaType, ObjectDigest};

    fn feature(name: &str) -> FeatureRef {
        FeatureRef::new(name, 1, 0).unwrap_or_else(|error| panic!("test feature failed: {error}"))
    }

    fn descriptor(media_type: &str) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(media_type)
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([1; 32]),
            1,
        )
    }

    #[test]
    fn resource_profile_rejects_duplicate_dimensions() {
        let enforcement = feature("aos.sandbox.enforcement.cgroup-v2");
        let limits = vec![
            Limit::new(
                LimitDimension::Memory,
                LimitValue::Bounded(1024),
                enforcement.clone(),
            ),
            Limit::new(
                LimitDimension::Memory,
                LimitValue::Bounded(2048),
                enforcement,
            ),
        ];

        assert_eq!(
            ResourceProfile::new(limits),
            Err(InvalidSpecModel::LimitsNotCanonical)
        );
    }

    #[test]
    fn isolated_network_rejects_endpoint_resources() {
        assert_eq!(
            NetworkProfile::new(
                NetworkKind::Isolated,
                vec![NetworkEndpointId::from_bytes([2; 16])],
                Vec::new(),
            ),
            Err(InvalidSpecModel::InvalidNetworkEndpoints)
        );
    }

    #[test]
    fn complete_spec_accepts_closed_profiles() {
        let identity = IdentityProfile::PrivateUserns {
            id_range_size: NonZeroU32::new(65_536)
                .unwrap_or_else(|| panic!("test range is nonzero")),
            unmappable_policy: UnmappableIdentityPolicy::Reject,
            required_features: Vec::new(),
        };
        let spec = SandboxSpec::new(
            feature("aos.sandbox.runtime.linux-systemd"),
            identity,
            ResourceProfile::new(Vec::new())
                .unwrap_or_else(|error| panic!("test resources failed: {error}")),
            descriptor("application/vnd.aos.sandbox.environment.v1+cbor"),
            descriptor("application/vnd.aos.sandbox.view.v1+cbor"),
            Vec::new(),
            NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new())
                .unwrap_or_else(|error| panic!("test network failed: {error}")),
            Vec::new(),
        );

        assert!(spec.is_ok());
    }
}

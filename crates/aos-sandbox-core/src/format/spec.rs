//! Canonical codec for portable sandbox specifications and nested profiles.

use std::num::NonZeroU32;

use crate::model::{
    IdentityProfile, Limit, LimitDimension, LimitValue, NetworkKind, NetworkProfile,
    ResourceProfile, SandboxSpec, UnmappableIdentityPolicy,
};
use crate::registry::DescriptorRole;
use crate::{AttachmentSlotId, GrantId, NetworkEndpointId};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{
    decode_descriptor_for_role, decode_feature, decode_vec, encode_descriptor, encode_feature,
    encode_slice, exact_bytes, semantics, unsigned_u32,
};

/// Encodes one sandbox specification in its exact portable v1 CBOR form.
#[must_use]
pub fn encode_sandbox_spec(spec: &SandboxSpec) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(9);
    encoder.unsigned(1);
    encode_feature(&mut encoder, spec.runtime_profile());
    encode_identity_profile(&mut encoder, spec.identity_profile());
    encode_resource_profile(&mut encoder, spec.resource_profile());
    encode_descriptor(&mut encoder, spec.environment());
    encode_descriptor(&mut encoder, spec.root_view());
    encode_ids(&mut encoder, spec.attachment_slots(), |id| id.as_bytes());
    encode_network_profile(&mut encoder, spec.network_profile());
    encode_slice(&mut encoder, spec.required_features(), encode_feature);
    encoder.finish()
}

/// Decodes and validates one exact portable v1 sandbox specification.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for deterministic-CBOR, schema, closed
/// registry, profile, descriptor, or canonical-collection violations.
pub fn decode_sandbox_spec(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<SandboxSpec, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(9)?;
    decoder.exact("sandbox specification version", 1)?;
    let runtime_profile = decode_feature(&mut decoder)?;
    let identity_profile = decode_identity_profile(&mut decoder)?;
    let resource_profile = decode_resource_profile(&mut decoder)?;
    let environment = decode_descriptor_for_role(&mut decoder, DescriptorRole::SandboxEnvironment)?;
    let root_view = decode_descriptor_for_role(&mut decoder, DescriptorRole::SandboxRootView)?;
    let attachment_slots = decode_ids(&mut decoder, AttachmentSlotId::from_bytes)?;
    let network_profile = decode_network_profile(&mut decoder)?;
    let required_features = decode_vec(&mut decoder, decode_feature)?;
    decoder.finish()?;
    SandboxSpec::new(
        runtime_profile,
        identity_profile,
        resource_profile,
        environment,
        root_view,
        attachment_slots,
        network_profile,
        required_features,
    )
    .map_err(|error| semantics("sandbox specification", error))
}

fn encode_identity_profile(encoder: &mut Encoder, profile: &IdentityProfile) {
    match profile {
        IdentityProfile::PrivateUserns {
            id_range_size,
            unmappable_policy,
            required_features,
        } => {
            encoder.array(4);
            encoder.unsigned(0);
            encoder.unsigned(u64::from(id_range_size.get()));
            encoder.unsigned(match unmappable_policy {
                UnmappableIdentityPolicy::Reject => 0,
                UnmappableIdentityPolicy::IsolatedSynthesizedPresentation => 1,
            });
            encode_slice(encoder, required_features, encode_feature);
        }
        IdentityProfile::Host { required_features } => {
            encoder.array(2);
            encoder.unsigned(1);
            encode_slice(encoder, required_features, encode_feature);
        }
    }
}

fn decode_identity_profile(
    decoder: &mut Decoder<'_>,
) -> Result<IdentityProfile, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("identity profile kind", 1)?;
    let profile = match (kind, length) {
        (0, 4) => {
            let range = unsigned_u32(decoder, "identity range size")?;
            let id_range_size =
                NonZeroU32::new(range).ok_or_else(|| CanonicalCborError::InvalidSemantics {
                    object: "identity profile",
                    message: "private user namespace range must be positive".to_owned(),
                })?;
            let unmappable_policy = match decoder.closed("unmappable identity policy", 1)? {
                0 => UnmappableIdentityPolicy::Reject,
                1 => UnmappableIdentityPolicy::IsolatedSynthesizedPresentation,
                _ => unreachable!("closed unmappable identity policy"),
            };
            let required_features = decode_vec(decoder, decode_feature)?;
            IdentityProfile::PrivateUserns {
                id_range_size,
                unmappable_policy,
                required_features,
            }
        }
        (1, 2) => IdentityProfile::Host {
            required_features: decode_vec(decoder, decode_feature)?,
        },
        _ => {
            return Err(CanonicalCborError::ArrayLength {
                expected: if kind == 0 { 4 } else { 2 },
                actual: length,
                offset,
            });
        }
    };
    profile
        .validate()
        .map_err(|error| semantics("identity profile", error))
}

pub(super) fn encode_resource_profile(encoder: &mut Encoder, profile: &ResourceProfile) {
    encode_slice(encoder, profile.limits(), encode_limit);
}

pub(super) fn decode_resource_profile(
    decoder: &mut Decoder<'_>,
) -> Result<ResourceProfile, CanonicalCborError> {
    let limits = decode_vec(decoder, decode_limit)?;
    ResourceProfile::new(limits).map_err(|error| semantics("resource profile", error))
}

fn encode_limit(encoder: &mut Encoder, limit: &Limit) {
    encoder.array(3);
    encoder.unsigned(limit_dimension_code(limit.dimension()));
    encode_limit_value(encoder, limit.value());
    encode_feature(encoder, limit.enforcement());
}

fn decode_limit(decoder: &mut Decoder<'_>) -> Result<Limit, CanonicalCborError> {
    decoder.array(3)?;
    let dimension = decode_limit_dimension(decoder)?;
    let value = decode_limit_value(decoder)?;
    let enforcement = decode_feature(decoder)?;
    Ok(Limit::new(dimension, value, enforcement))
}

fn encode_limit_value(encoder: &mut Encoder, value: LimitValue) {
    match value {
        LimitValue::Inherited => {
            encoder.array(1);
            encoder.unsigned(0);
        }
        LimitValue::Bounded(value) => {
            encoder.array(2);
            encoder.unsigned(1);
            encoder.unsigned(value);
        }
        LimitValue::Unlimited(grant) => {
            encoder.array(2);
            encoder.unsigned(2);
            encoder.bytes(grant.as_bytes());
        }
    }
}

fn decode_limit_value(decoder: &mut Decoder<'_>) -> Result<LimitValue, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("limit value kind", 2)?;
    match (kind, length) {
        (0, 1) => Ok(LimitValue::Inherited),
        (1, 2) => decoder.unsigned().map(LimitValue::Bounded),
        (2, 2) => Ok(LimitValue::Unlimited(GrantId::from_bytes(exact_bytes(
            decoder, 16,
        )?))),
        _ => Err(CanonicalCborError::ArrayLength {
            expected: if kind == 0 { 1 } else { 2 },
            actual: length,
            offset,
        }),
    }
}

fn encode_network_profile(encoder: &mut Encoder, profile: &NetworkProfile) {
    encoder.array(3);
    encoder.unsigned(match profile.kind() {
        NetworkKind::Isolated => 0,
        NetworkKind::Project => 1,
        NetworkKind::Outbound => 2,
        NetworkKind::Published => 3,
        NetworkKind::Host => 4,
    });
    encode_ids(encoder, profile.endpoint_ids(), |id| id.as_bytes());
    encode_slice(encoder, profile.required_features(), encode_feature);
}

fn decode_network_profile(decoder: &mut Decoder<'_>) -> Result<NetworkProfile, CanonicalCborError> {
    decoder.array(3)?;
    let kind = match decoder.closed("network kind", 4)? {
        0 => NetworkKind::Isolated,
        1 => NetworkKind::Project,
        2 => NetworkKind::Outbound,
        3 => NetworkKind::Published,
        4 => NetworkKind::Host,
        _ => unreachable!("closed network kind"),
    };
    let endpoint_ids = decode_ids(decoder, NetworkEndpointId::from_bytes)?;
    let required_features = decode_vec(decoder, decode_feature)?;
    NetworkProfile::new(kind, endpoint_ids, required_features)
        .map_err(|error| semantics("network profile", error))
}

fn limit_dimension_code(dimension: LimitDimension) -> u64 {
    dimension as u64
}

fn decode_limit_dimension(decoder: &mut Decoder<'_>) -> Result<LimitDimension, CanonicalCborError> {
    Ok(match decoder.closed("limit dimension", 15)? {
        0 => LimitDimension::Bytes,
        1 => LimitDimension::Inodes,
        2 => LimitDimension::Processes,
        3 => LimitDimension::Memory,
        4 => LimitDimension::CpuWeight,
        5 => LimitDimension::CpuQuota,
        6 => LimitDimension::IoWeight,
        7 => LimitDimension::IoBandwidth,
        8 => LimitDimension::MountCount,
        9 => LimitDimension::OpenFiles,
        10 => LimitDimension::FuseRequests,
        11 => LimitDimension::FuseMemory,
        12 => LimitDimension::CacheBytes,
        13 => LimitDimension::SnapshotCount,
        14 => LimitDimension::ChildCount,
        15 => LimitDimension::ExecutionCount,
        _ => unreachable!("closed limit dimension"),
    })
}

fn encode_ids<T>(encoder: &mut Encoder, values: &[T], bytes: fn(&T) -> &[u8; 16]) {
    encoder.array(values.len());
    for value in values {
        encoder.bytes(bytes(value));
    }
}

fn decode_ids<T>(
    decoder: &mut Decoder<'_>,
    construct: fn([u8; 16]) -> T,
) -> Result<Vec<T>, CanonicalCborError> {
    let length = decoder.array_len()?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(construct(exact_bytes(decoder, 16)?));
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InvalidSpecModel;
    use crate::{FeatureRef, MediaType, ObjectDescriptor, ObjectDigest};

    fn feature() -> FeatureRef {
        FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0)
            .unwrap_or_else(|error| panic!("test feature failed: {error}"))
    }

    fn descriptor(kind: &str) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(format!("application/vnd.aos.sandbox.{kind}.v1+cbor"))
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([1; 32]),
            1,
        )
    }

    fn spec() -> SandboxSpec {
        SandboxSpec::new(
            feature(),
            IdentityProfile::PrivateUserns {
                id_range_size: NonZeroU32::new(65_536)
                    .unwrap_or_else(|| panic!("test range is positive")),
                unmappable_policy: UnmappableIdentityPolicy::Reject,
                required_features: Vec::new(),
            },
            ResourceProfile::new(vec![Limit::new(
                LimitDimension::Memory,
                LimitValue::Bounded(1 << 20),
                FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0)
                    .unwrap_or_else(|error| panic!("test feature failed: {error}")),
            )])
            .unwrap_or_else(|error| panic!("test resources failed: {error}")),
            descriptor("environment"),
            descriptor("view"),
            vec![AttachmentSlotId::from_bytes([2; 16])],
            NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new())
                .unwrap_or_else(|error| panic!("test network failed: {error}")),
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test spec failed: {error}"))
    }

    #[test]
    fn sandbox_spec_round_trips_exact_profiles() {
        let spec = spec();
        let encoded = encode_sandbox_spec(&spec);

        assert_eq!(
            decode_sandbox_spec(&encoded, DecodeLimits::default()),
            Ok(spec)
        );
    }

    #[test]
    fn reserved_limit_dimensions_fail_closed() {
        let mut encoder = Encoder::new();
        encoder.array(1);
        encoder.array(3);
        encoder.unsigned(16);
        encoder.array(2);
        encoder.unsigned(1);
        encoder.unsigned(1);
        encode_feature(&mut encoder, &feature());
        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes, DecodeLimits::default())
            .unwrap_or_else(|error| panic!("test decoder failed: {error}"));

        assert!(matches!(
            decode_resource_profile(&mut decoder),
            Err(CanonicalCborError::UnknownRegistryValue {
                registry: "limit dimension",
                value: 16,
                ..
            })
        ));
    }

    #[test]
    fn isolated_network_semantics_remain_fail_closed() {
        assert_eq!(
            NetworkProfile::new(
                NetworkKind::Isolated,
                vec![NetworkEndpointId::from_bytes([1; 16])],
                Vec::new(),
            ),
            Err(InvalidSpecModel::InvalidNetworkEndpoints)
        );
    }
}

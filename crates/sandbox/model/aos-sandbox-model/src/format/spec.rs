//! Canonical codec for portable sandbox specifications and nested profiles.

use std::num::NonZeroU32;

use crate::model::{
    GuestExecutionIdentityPolicyV1, IdentityProfile, Limit, LimitDimension, LimitValue,
    NetworkKind, NetworkProfile, ResourceProfile, SandboxSpec, UnmappableIdentityPolicy,
};
use crate::registry::{DescriptorRole, PortableMediaType};
use crate::{AttachmentSlotId, GrantId, MAX_EXECUTION_SUPPLEMENTARY_GROUPS, NetworkEndpointId};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{
    decode_descriptor_for_role, decode_feature, decode_vec, encode_descriptor, encode_feature,
    encode_slice, exact_bytes, semantics, unsigned_u32,
};

/// Returns the media type selected by a sandbox spec's explicit policy version.
#[must_use]
pub fn sandbox_spec_media_type(spec: &SandboxSpec) -> PortableMediaType {
    if spec.guest_execution_identity().is_some() {
        PortableMediaType::SandboxSpecV2
    } else {
        PortableMediaType::SandboxSpec
    }
}

/// Encodes one sandbox specification in its exact portable v1 or v2 CBOR form.
#[must_use]
pub fn encode_sandbox_spec(spec: &SandboxSpec) -> Vec<u8> {
    let mut encoder = Encoder::new();
    if spec.guest_execution_identity().is_some() {
        encoder.array(10);
        encoder.unsigned(2);
    } else {
        encoder.array(9);
        encoder.unsigned(1);
    }
    encode_feature(&mut encoder, spec.runtime_profile());
    encode_identity_profile(&mut encoder, spec.identity_profile());
    if let Some(policy) = spec.guest_execution_identity() {
        encode_guest_execution_identity(&mut encoder, policy);
    }
    encode_resource_profile(&mut encoder, spec.resource_profile());
    encode_descriptor(&mut encoder, spec.environment());
    encode_descriptor(&mut encoder, spec.root_view());
    encode_ids(&mut encoder, spec.attachment_slots(), |id| id.as_bytes());
    encode_network_profile(&mut encoder, spec.network_profile());
    encode_slice(&mut encoder, spec.required_features(), encode_feature);
    encoder.finish()
}

/// Bounds one canonical specification decode and its comparison encoding.
///
/// This passive byte invoice uses the same decoder limits and collection
/// element layouts as [`decode_sandbox_spec`]. Whole-input validation precedes
/// every typed vector reservation. Its aggregate item bound therefore covers
/// the co-live identity, limit, attachment, endpoint and feature vectors,
/// including a malformed typed element after those reservations. The model
/// constructors validate sorted slices without constructing another index.
///
/// The input is borrowed and excluded. The bound includes the decoder's
/// recursive validation frames, model move/construction planes, text backing,
/// canonical encoding growth and diagnostic formatting. It grants no parsing,
/// currentness or authority. No Rust carrier is a namespace entry.
///
/// Returns `None` for an oversized input or checked arithmetic overflow.
#[must_use]
pub fn sandbox_spec_decoding_receiving_bytes_v2(
    input_bytes: usize,
    limits: DecodeLimits,
) -> Option<usize> {
    use std::mem::size_of;

    if input_bytes > limits.maximum_bytes {
        return None;
    }
    let validation = super::cbor::validation_receiving_bytes_v1(input_bytes, limits)?;
    let slots = input_bytes.min(limits.maximum_total_items);
    let element = size_of::<crate::FeatureRef>()
        .max(size_of::<Limit>())
        .max(size_of::<AttachmentSlotId>())
        .max(size_of::<NetworkEndpointId>())
        .max(size_of::<u32>());
    // The decoder's partial vectors move into nested profiles and then the
    // complete model. Three planes include those construction temporaries;
    // their capacities are bounded by the one prevalidated aggregate extent.
    let vectors = slots.checked_mul(element)?.checked_mul(3)?;
    let fixed = size_of::<SandboxSpec>().checked_mul(3)?
        .checked_add(size_of::<Decoder<'_>>())?
        .checked_add(size_of::<CanonicalCborError>().checked_mul(4)?)?;
    // Disjoint decoded strings fit in input bytes. Four planes also cover the
    // comparison encoder's geometric Vec growth and a formatted schema error.
    validation.checked_add(vectors)?.checked_add(fixed)?
        .checked_add(input_bytes.checked_mul(4)?)?
        .checked_add(4 * 4_096)
}

/// Decodes and validates one exact portable v1 or v2 sandbox specification.
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
    let length = decoder.array_len()?;
    let version = decoder.closed("sandbox specification version", 2)?;
    if !matches!((version, length), (1, 9) | (2, 10)) {
        return Err(CanonicalCborError::InvalidSemantics {
            object: "sandbox specification",
            message: "version and field count disagree".to_owned(),
        });
    }
    let runtime_profile = decode_feature(&mut decoder)?;
    let identity_profile = decode_identity_profile(&mut decoder)?;
    let guest_execution_identity = if version == 2 {
        Some(decode_guest_execution_identity(&mut decoder)?)
    } else {
        None
    };
    let resource_profile = decode_resource_profile(&mut decoder)?;
    let environment = decode_descriptor_for_role(&mut decoder, DescriptorRole::SandboxEnvironment)?;
    let root_view = decode_descriptor_for_role(&mut decoder, DescriptorRole::SandboxRootView)?;
    let attachment_slots = decode_ids(&mut decoder, AttachmentSlotId::from_bytes)?;
    let network_profile = decode_network_profile(&mut decoder)?;
    let required_features = decode_vec(&mut decoder, decode_feature)?;
    decoder.finish()?;
    let spec = SandboxSpec::new(
        runtime_profile,
        identity_profile,
        resource_profile,
        environment,
        root_view,
        attachment_slots,
        network_profile,
        required_features,
    )
    .map_err(|error| semantics("sandbox specification", error))?;
    match guest_execution_identity {
        Some(policy) => spec
            .with_guest_execution_identity(policy)
            .map_err(|error| semantics("sandbox specification", error)),
        None => Ok(spec),
    }
}

fn encode_guest_execution_identity(encoder: &mut Encoder, policy: &GuestExecutionIdentityPolicyV1) {
    encoder.array(4);
    encoder.unsigned(1);
    encoder.unsigned(u64::from(policy.user_id()));
    encoder.unsigned(u64::from(policy.primary_group_id()));
    encode_slice(
        encoder,
        policy.supplementary_group_ids(),
        |encoder, group| {
            encoder.unsigned(u64::from(*group));
        },
    );
}

fn decode_guest_execution_identity(
    decoder: &mut Decoder<'_>,
) -> Result<GuestExecutionIdentityPolicyV1, CanonicalCborError> {
    decoder.array(4)?;
    decoder.exact("guest execution identity policy version", 1)?;
    let user_id = unsigned_u32(decoder, "guest execution user ID")?;
    let primary_group_id = unsigned_u32(decoder, "guest execution primary group ID")?;
    let count = decoder.bounded_array_len(MAX_EXECUTION_SUPPLEMENTARY_GROUPS)?;
    let mut supplementary_group_ids = Vec::with_capacity(count);
    for _ in 0..count {
        supplementary_group_ids.push(unsigned_u32(
            decoder,
            "guest execution supplementary group ID",
        )?);
    }
    GuestExecutionIdentityPolicyV1::new(user_id, primary_group_id, supplementary_group_ids)
        .map_err(|error| semantics("guest execution identity policy", error))
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

    #[test]
    fn specification_receiving_uses_actual_core_extent() {
        let limits = DecodeLimits::default();
        let small = sandbox_spec_decoding_receiving_bytes_v2(16 * 1024, limits).unwrap();
        let large = sandbox_spec_decoding_receiving_bytes_v2(512 * 1024, limits).unwrap();
        assert!(large > small);
        assert!(sandbox_spec_decoding_receiving_bytes_v2(limits.maximum_bytes + 1, limits).is_none());
        assert!(sandbox_spec_decoding_receiving_bytes_v2(usize::MAX, DecodeLimits {
            maximum_bytes: usize::MAX,
            maximum_total_items: usize::MAX,
            maximum_depth: usize::MAX,
            ..limits
        }).is_none());
    }

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
    fn spec_receiving_bound_uses_complete_input_before_schema_reservation() {
        let limits = DecodeLimits::default();
        let encoded = encode_sandbox_spec(&spec());
        assert!(sandbox_spec_decoding_memory_bound_v4(encoded.len(), limits).unwrap()
            > encoded.len() + std::mem::size_of::<SandboxSpec>());

        // A huge advertised absent array is rejected by the canonical pass,
        // before decode_ids or decode_vec can reserve its announced population.
        let truncated = [0x9a, 0xff, 0xff, 0xff, 0xff];
        assert!(decode_sandbox_spec(&truncated, limits).is_err());
        let tiny = sandbox_spec_decoding_memory_bound_v4(truncated.len(), limits).unwrap();
        assert!(tiny < sandbox_spec_decoding_memory_bound_v4(encoded.len(), limits).unwrap());
        assert!(sandbox_spec_decoding_memory_bound_v4(usize::MAX, limits).is_none());
    }

    #[test]
    fn sandbox_spec_round_trips_exact_profiles() {
        let spec = spec();
        let encoded = encode_sandbox_spec(&spec);

        assert_eq!(&encoded[..2], &[0x89, 0x01]);
        assert_eq!(
            decode_sandbox_spec(&encoded, DecodeLimits::default()),
            Ok(spec)
        );
    }

    #[test]
    fn sandbox_spec_v2_round_trips_explicit_guest_identity() {
        let policy = GuestExecutionIdentityPolicyV1::new(1000, 1000, vec![4, 44]).unwrap();
        let spec = spec().with_guest_execution_identity(policy).unwrap();
        let encoded = encode_sandbox_spec(&spec);

        assert_eq!(&encoded[..2], &[0x8a, 0x02]);
        assert_eq!(
            decode_sandbox_spec(&encoded, DecodeLimits::default()),
            Ok(spec)
        );

        let mut wrong_version = encoded.clone();
        wrong_version[1] = 1;
        assert!(decode_sandbox_spec(&wrong_version, DecodeLimits::default()).is_err());
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

/// Bounds simultaneous specification decode, semantic and canonical-copy memory.
///
/// The whole canonical-CBOR pass precedes every schema reservation. Even a
/// schema-invalid array item therefore consumes an actual input byte. This
/// bounds all collection prefixes by that aggregate item population, including
/// the current rejected collection; it never trusts an announced absent tail.
/// `None` reports checked layout arithmetic overflow. No model is constructed.
#[must_use]
pub fn sandbox_spec_decoding_memory_bound_v4(input_bytes: usize, limits: DecodeLimits) -> Option<usize> {
    use std::mem::size_of;
    let row = [size_of::<crate::FeatureRef>(), size_of::<Limit>(),
        size_of::<AttachmentSlotId>(), size_of::<NetworkEndpointId>(),
        size_of::<u32>(), size_of::<crate::ObjectDescriptor>()].into_iter().max()?;
    let collections = input_bytes.min(limits.maximum_total_items)
        .checked_mul(row)?.checked_mul(2)?;
    // Current text, completed owned text, and the old/new canonical output
    // allocation coexist. Compiled root constructors are separate from backing.
    collections.checked_add(input_bytes.checked_mul(4)?)?
        .checked_add(size_of::<SandboxSpec>().checked_mul(2)?)?
        .checked_add(super::cbor::validation_receiving_bytes_v1(input_bytes, limits)?)
}

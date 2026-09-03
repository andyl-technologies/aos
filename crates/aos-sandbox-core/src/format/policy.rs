//! Canonical codecs for resolved policy and advisory optimization objects.

use crate::model::{
    ExplanationReason, ExplanationReasonCode, Optimization, OptimizationKind, OptimizationProfile,
    Policy, PolicyViewAction, RevocationMode, RevocationPolicy,
};
use crate::{
    AttachmentSlotId, ExportId, Grant, GrantId, OperationSet, ResourceId, ResourceKind, Selector,
};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::spec::{decode_resource_profile, encode_resource_profile};
use super::tree::{
    decode_descriptor, decode_feature, decode_path, decode_vec, encode_descriptor, encode_feature,
    encode_path, encode_slice, exact_bytes, semantics,
};
use super::view::{
    decode_cache_domain, decode_view_mutation, encode_cache_domain, view_mutation_code,
};

/// Encodes one resolved policy in its exact portable v1 CBOR form.
#[must_use]
pub fn encode_policy(policy: &Policy) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(11);
    encoder.unsigned(1);
    encode_slice(&mut encoder, policy.required_features(), encode_feature);
    encode_slice(&mut encoder, policy.input_commitments(), encode_descriptor);
    encode_set(&mut encoder, policy.effective_grants(), encode_grant);
    encode_set(&mut encoder, policy.delegable_grants(), encode_grant);
    encode_resource_profile(&mut encoder, policy.limits());
    encode_slice(
        &mut encoder,
        policy.view_actions(),
        encode_policy_view_action,
    );
    encode_cache_domain(&mut encoder, policy.cache_domain());
    encode_revocation(&mut encoder, policy.revocation());
    match policy.optimization_digest() {
        Some(descriptor) => encode_descriptor(&mut encoder, descriptor),
        None => encoder.null(),
    }
    encode_slice(&mut encoder, policy.explanation_reasons(), encode_reason);
    encoder.finish()
}

/// Decodes and validates one exact portable v1 resolved policy.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for deterministic-CBOR, schema, closed
/// registry, canonical-set, grant-subset, limit, or explanation violations.
pub fn decode_policy(bytes: &[u8], limits: DecodeLimits) -> Result<Policy, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(11)?;
    decoder.exact("policy version", 1)?;
    let required_features = decode_vec(&mut decoder, decode_feature)?;
    let input_commitments = decode_vec(&mut decoder, decode_descriptor)?;
    let effective_grants = decode_set(&mut decoder, decode_grant)?;
    let delegable_grants = decode_set(&mut decoder, decode_grant)?;
    let limits = decode_resource_profile(&mut decoder)?;
    let view_actions = decode_vec(&mut decoder, decode_policy_view_action)?;
    let cache_domain = decode_cache_domain(&mut decoder)?;
    let revocation = decode_revocation(&mut decoder)?;
    let optimization_digest = decoder.nullable(decode_descriptor)?;
    let explanation_reasons = decode_vec(&mut decoder, decode_reason)?;
    decoder.finish()?;
    Policy::new(
        required_features,
        input_commitments,
        effective_grants,
        delegable_grants,
        limits,
        view_actions,
        cache_domain,
        revocation,
        optimization_digest,
        explanation_reasons,
    )
    .map_err(|error| semantics("policy", error))
}

/// Encodes one advisory optimization object in portable v1 CBOR form.
#[must_use]
pub fn encode_optimization(profile: &OptimizationProfile) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(2);
    encoder.unsigned(1);
    encode_set(&mut encoder, profile.entries(), encode_optimization_entry);
    encoder.finish()
}

/// Decodes and validates one exact portable v1 optimization object.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for deterministic-CBOR, schema, closed
/// registry, canonical-set, selector, or duplicate-action violations.
pub fn decode_optimization(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<OptimizationProfile, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(2)?;
    decoder.exact("optimization version", 1)?;
    let entries = decode_set(&mut decoder, decode_optimization_entry)?;
    decoder.finish()?;
    OptimizationProfile::new(entries).map_err(|error| semantics("optimization", error))
}

fn encode_grant(encoder: &mut Encoder, grant: &Grant) {
    encoder.array(5);
    encoder.bytes(grant.id().as_bytes());
    encoder.unsigned(grant.resource_kind() as u64);
    encoder.unsigned(u64::from(grant.operations().bits()));
    encode_selector(encoder, grant.selector());
    encoder.boolean(grant.delegable());
}

fn decode_grant(decoder: &mut Decoder<'_>) -> Result<Grant, CanonicalCborError> {
    decoder.array(5)?;
    let id = GrantId::from_bytes(exact_bytes(decoder, 16)?);
    let resource_kind = decode_resource_kind(decoder)?;
    let bits = decoder.closed("operation bitmap", 0x7fff)? as u16;
    let operations =
        OperationSet::from_bits(bits).map_err(|error| semantics("operation bitmap", error))?;
    let selector = decode_selector(decoder)?;
    let delegable = decoder.boolean()?;
    Grant::new(id, resource_kind, operations, selector, delegable)
        .map_err(|error| semantics("grant", error))
}

fn encode_selector(encoder: &mut Encoder, selector: &Selector) {
    match selector {
        Selector::Resource { resource } => {
            encoder.array(2);
            encoder.unsigned(0);
            encoder.bytes(resource.as_bytes());
        }
        Selector::Tree { tree } => {
            encoder.array(2);
            encoder.unsigned(1);
            encode_descriptor(encoder, tree);
        }
        Selector::Path { export, prefix } => {
            encoder.array(3);
            encoder.unsigned(2);
            encoder.bytes(export.as_bytes());
            encode_path(encoder, prefix);
        }
        Selector::Profile { feature, body } => {
            encoder.array(3);
            encoder.unsigned(3);
            encode_feature(encoder, feature);
            encode_descriptor(encoder, body);
        }
    }
}

fn decode_selector(decoder: &mut Decoder<'_>) -> Result<Selector, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("selector kind", 3)?;
    match (kind, length) {
        (0, 2) => Ok(Selector::Resource {
            resource: ResourceId::from_bytes(exact_bytes(decoder, 16)?),
        }),
        (1, 2) => Ok(Selector::Tree {
            tree: decode_descriptor(decoder)?,
        }),
        (2, 3) => Ok(Selector::Path {
            export: ExportId::from_bytes(exact_bytes(decoder, 16)?),
            prefix: decode_path(decoder)?,
        }),
        (3, 3) => Ok(Selector::Profile {
            feature: decode_feature(decoder)?,
            body: decode_descriptor(decoder)?,
        }),
        _ => Err(CanonicalCborError::ArrayLength {
            expected: if kind <= 1 { 2 } else { 3 },
            actual: length,
            offset,
        }),
    }
}

fn decode_resource_kind(decoder: &mut Decoder<'_>) -> Result<ResourceKind, CanonicalCborError> {
    Ok(match decoder.closed("resource kind", 14)? {
        0 => ResourceKind::Sandbox,
        1 => ResourceKind::Execution,
        2 => ResourceKind::Snapshot,
        3 => ResourceKind::Tree,
        4 => ResourceKind::LiveExport,
        5 => ResourceKind::PrivateDelta,
        6 => ResourceKind::Secret,
        7 => ResourceKind::Device,
        8 => ResourceKind::NetworkEndpoint,
        9 => ResourceKind::IpcService,
        10 => ResourceKind::CacheRead,
        11 => ResourceKind::CachePublish,
        12 => ResourceKind::Environment,
        13 => ResourceKind::AttachmentSlot,
        14 => ResourceKind::ChildDelegation,
        _ => unreachable!("closed resource kind"),
    })
}

fn encode_policy_view_action(encoder: &mut Encoder, action: &PolicyViewAction) {
    match action {
        PolicyViewAction::Include { source, prefix } => {
            encoder.array(3);
            encoder.unsigned(0);
            encoder.bytes(source.as_bytes());
            encode_path(encoder, prefix);
        }
        PolicyViewAction::Exclude { prefix } => {
            encoder.array(2);
            encoder.unsigned(1);
            encode_path(encoder, prefix);
        }
        PolicyViewAction::Attach {
            source,
            destination_slot,
            mode,
        } => {
            encoder.array(4);
            encoder.unsigned(2);
            encoder.bytes(source.as_bytes());
            encoder.bytes(destination_slot.as_bytes());
            encoder.unsigned(view_mutation_code(*mode));
        }
        PolicyViewAction::Present {
            prefix,
            presentation_profile,
        } => {
            encoder.array(3);
            encoder.unsigned(3);
            encode_path(encoder, prefix);
            encode_feature(encoder, presentation_profile);
        }
    }
}

fn decode_policy_view_action(
    decoder: &mut Decoder<'_>,
) -> Result<PolicyViewAction, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    let kind = decoder.closed("policy view action", 3)?;
    match (kind, length) {
        (0, 3) => Ok(PolicyViewAction::Include {
            source: ResourceId::from_bytes(exact_bytes(decoder, 16)?),
            prefix: decode_path(decoder)?,
        }),
        (1, 2) => Ok(PolicyViewAction::Exclude {
            prefix: decode_path(decoder)?,
        }),
        (2, 4) => Ok(PolicyViewAction::Attach {
            source: ResourceId::from_bytes(exact_bytes(decoder, 16)?),
            destination_slot: AttachmentSlotId::from_bytes(exact_bytes(decoder, 16)?),
            mode: decode_view_mutation(decoder)?,
        }),
        (3, 3) => Ok(PolicyViewAction::Present {
            prefix: decode_path(decoder)?,
            presentation_profile: decode_feature(decoder)?,
        }),
        _ => Err(CanonicalCborError::ArrayLength {
            expected: match kind {
                1 => 2,
                2 => 4,
                _ => 3,
            },
            actual: length,
            offset,
        }),
    }
}

fn encode_revocation(encoder: &mut Encoder, policy: RevocationPolicy) {
    encoder.array(2);
    encoder.unsigned(match policy.mode() {
        RevocationMode::DenyNew => 0,
        RevocationMode::Freeze => 1,
        RevocationMode::Stop => 2,
    });
    encoder.unsigned(policy.grace_nanos());
}

fn decode_revocation(decoder: &mut Decoder<'_>) -> Result<RevocationPolicy, CanonicalCborError> {
    decoder.array(2)?;
    let mode = match decoder.closed("revocation mode", 2)? {
        0 => RevocationMode::DenyNew,
        1 => RevocationMode::Freeze,
        2 => RevocationMode::Stop,
        _ => unreachable!("closed revocation mode"),
    };
    Ok(RevocationPolicy::new(mode, decoder.unsigned()?))
}

fn encode_optimization_entry(encoder: &mut Encoder, optimization: &Optimization) {
    encoder.array(3);
    encoder.unsigned(match optimization.kind() {
        OptimizationKind::PrefetchMetadata => 0,
        OptimizationKind::PrefetchContent => 1,
        OptimizationKind::Readahead => 2,
        OptimizationKind::DirectoryIndex => 3,
        OptimizationKind::Passthrough => 4,
        OptimizationKind::Keepalive => 5,
        OptimizationKind::CacheWeight => 6,
        OptimizationKind::WorkerPooling => 7,
    });
    encode_selector(encoder, optimization.target());
    encoder.unsigned(optimization.bounded_value());
}

fn decode_optimization_entry(
    decoder: &mut Decoder<'_>,
) -> Result<Optimization, CanonicalCborError> {
    decoder.array(3)?;
    let kind = match decoder.closed("optimization kind", 7)? {
        0 => OptimizationKind::PrefetchMetadata,
        1 => OptimizationKind::PrefetchContent,
        2 => OptimizationKind::Readahead,
        3 => OptimizationKind::DirectoryIndex,
        4 => OptimizationKind::Passthrough,
        5 => OptimizationKind::Keepalive,
        6 => OptimizationKind::CacheWeight,
        7 => OptimizationKind::WorkerPooling,
        _ => unreachable!("closed optimization kind"),
    };
    let target = decode_selector(decoder)?;
    let bounded_value = decoder.unsigned()?;
    Ok(Optimization::new(kind, target, bounded_value))
}

fn encode_reason(encoder: &mut Encoder, reason: &ExplanationReason) {
    encoder.array(2);
    encoder.unsigned(match reason.code() {
        ExplanationReasonCode::SiteCeiling => 0,
        ExplanationReasonCode::ProjectCeiling => 1,
        ExplanationReasonCode::AncestorCeiling => 2,
        ExplanationReasonCode::CallerGrant => 3,
        ExplanationReasonCode::ResourceLimit => 4,
        ExplanationReasonCode::DisclosureDomain => 5,
        ExplanationReasonCode::Revocation => 6,
        ExplanationReasonCode::BackendRequirement => 7,
        ExplanationReasonCode::AttachmentConflict => 8,
        ExplanationReasonCode::EnvironmentPolicy => 9,
        ExplanationReasonCode::Default => 10,
    });
    match reason.source() {
        Some(source) => encode_descriptor(encoder, source),
        None => encoder.null(),
    }
}

fn decode_reason(decoder: &mut Decoder<'_>) -> Result<ExplanationReason, CanonicalCborError> {
    decoder.array(2)?;
    let code = match decoder.closed("explanation reason", 10)? {
        0 => ExplanationReasonCode::SiteCeiling,
        1 => ExplanationReasonCode::ProjectCeiling,
        2 => ExplanationReasonCode::AncestorCeiling,
        3 => ExplanationReasonCode::CallerGrant,
        4 => ExplanationReasonCode::ResourceLimit,
        5 => ExplanationReasonCode::DisclosureDomain,
        6 => ExplanationReasonCode::Revocation,
        7 => ExplanationReasonCode::BackendRequirement,
        8 => ExplanationReasonCode::AttachmentConflict,
        9 => ExplanationReasonCode::EnvironmentPolicy,
        10 => ExplanationReasonCode::Default,
        _ => unreachable!("closed explanation reason"),
    };
    let source = decoder.nullable(decode_descriptor)?;
    Ok(ExplanationReason::new(code, source))
}

fn encode_set<T>(encoder: &mut Encoder, values: &[T], encode: fn(&mut Encoder, &T)) {
    let mut encoded_items = values
        .iter()
        .map(|value| {
            let mut item = Encoder::new();
            encode(&mut item, value);
            item.finish()
        })
        .collect::<Vec<_>>();
    encoded_items.sort();
    encoder.array(encoded_items.len());
    for item in encoded_items {
        encoder.raw(&item);
    }
}

fn decode_set<T>(
    decoder: &mut Decoder<'_>,
    decode: fn(&mut Decoder<'_>) -> Result<T, CanonicalCborError>,
) -> Result<Vec<T>, CanonicalCborError> {
    let length = decoder.array_len()?;
    let mut values = Vec::with_capacity(length);
    let mut prior: Option<Vec<u8>> = None;
    for _ in 0..length {
        let start = decoder.position();
        let value = decode(decoder)?;
        let end = decoder.position();
        let encoded = decoder.encoded_range(start, end);
        if prior.as_deref().is_some_and(|item| item >= encoded) {
            return Err(CanonicalCborError::SetOrder { offset: start });
        }
        prior = Some(encoded.to_vec());
        values.push(value);
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ViewMutation;
    use crate::model::{
        CacheDomain, CacheDomainKind, Limit, LimitDimension, LimitValue, ResourceProfile,
    };
    use crate::{CacheDomainId, FeatureRef, MediaType, ObjectDescriptor, ObjectDigest, Operation};

    fn descriptor(byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.policy.v1+cbor")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([byte; 32]),
            1,
        )
    }

    fn grant(id: u8) -> Grant {
        Grant::new(
            GrantId::from_bytes([id; 16]),
            ResourceKind::Tree,
            OperationSet::one(Operation::ContentRead),
            Selector::Tree {
                tree: descriptor(id),
            },
            true,
        )
        .unwrap_or_else(|error| panic!("test grant failed: {error}"))
    }

    fn policy() -> Policy {
        Policy::new(
            Vec::new(),
            vec![descriptor(9)],
            vec![grant(2), grant(1)],
            vec![grant(1)],
            ResourceProfile::new(vec![Limit::new(
                LimitDimension::Memory,
                LimitValue::Bounded(1024),
                FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0)
                    .unwrap_or_else(|error| panic!("test feature failed: {error}")),
            )])
            .unwrap_or_else(|error| panic!("test resources failed: {error}")),
            vec![PolicyViewAction::Attach {
                source: ResourceId::from_bytes([4; 16]),
                destination_slot: AttachmentSlotId::from_bytes([5; 16]),
                mode: ViewMutation::ReadOnly,
            }],
            CacheDomain::new(CacheDomainKind::Project, CacheDomainId::from_bytes([6; 16])),
            RevocationPolicy::new(RevocationMode::Freeze, 1_000),
            None,
            vec![ExplanationReason::new(
                ExplanationReasonCode::ProjectCeiling,
                Some(descriptor(9)),
            )],
        )
        .unwrap_or_else(|error| panic!("test policy failed: {error}"))
    }

    #[test]
    fn policy_encoder_canonicalizes_grant_set_order() {
        let policy = policy();
        let encoded = encode_policy(&policy);
        let decoded = decode_policy(&encoded, DecodeLimits::default())
            .unwrap_or_else(|error| panic!("test policy decode failed: {error}"));

        assert_eq!(
            decoded.effective_grants()[0].id(),
            GrantId::from_bytes([1; 16])
        );
        assert_eq!(
            decoded.effective_grants()[1].id(),
            GrantId::from_bytes([2; 16])
        );
    }

    #[test]
    fn optimization_round_trip_preserves_closed_action() {
        let profile = OptimizationProfile::new(vec![Optimization::new(
            OptimizationKind::PrefetchMetadata,
            Selector::Resource {
                resource: ResourceId::from_bytes([7; 16]),
            },
            42,
        )])
        .unwrap_or_else(|error| panic!("test optimization failed: {error}"));
        let encoded = encode_optimization(&profile);

        assert_eq!(
            decode_optimization(&encoded, DecodeLimits::default()),
            Ok(profile)
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_grant_set_order() {
        let policy = policy();
        let canonical = encode_policy(&policy);
        let decoded = decode_policy(&canonical, DecodeLimits::default());
        assert!(decoded.is_ok());

        let mut encoder = Encoder::new();
        encoder.array(2);
        encode_grant(&mut encoder, &grant(2));
        encode_grant(&mut encoder, &grant(1));
        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes, DecodeLimits::default())
            .unwrap_or_else(|error| panic!("test decoder failed: {error}"));
        assert!(matches!(
            decode_set(&mut decoder, decode_grant),
            Err(CanonicalCborError::SetOrder { .. })
        ));
    }
}

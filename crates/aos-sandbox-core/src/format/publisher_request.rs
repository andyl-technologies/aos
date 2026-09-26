//! Canonical publisher admission request and commitment-preimage encoding.
//!
//! This protocol preimage is not a stored portable object. Its exact v1 schema
//! excludes the derived request commitment and every signature, avoiding a
//! self-referential hash. Target, authority, descriptor and feature framing are
//! shared with the publisher-domain plan codec.
//!
//! ```text
//! [1, capability, cache_resource, challenge, [protocol_major, protocol_minor],
//!  [publisher_principal, publisher_instance, node, project,
//!   [1, cache_domain_id], isolation_policy],
//!  [holder, channel, operation, reservation,
//!   [content_media_type, 1, content_sha256, content_size],
//!   source_authorization, maximum_bytes],
//!  [policy, policy_generation, controller_generation, revocation_scope,
//!   revocation_generation, root_registry_generation],
//!  issued_seconds, expires_seconds,
//!  [[feature_namespace, feature_major, feature_minor], ...]]
//! ```
//!
//! Identities are 16-byte strings; challenge, channel and digests are 32-byte
//! strings. Times are signed Unix seconds. Decoding checks structural semantics
//! and reconstructs the commitment; it grants no authentication, currentness,
//! reservation, or publication authority.

use crate::publisher::{
    PublisherAdmissionClaimV1, PublisherAdmissionRequestDraftV1, PublisherAdmissionRequestV1,
    PublisherAuthorityBindings, PublisherChallengeV1, PublisherTarget,
};
use crate::{
    CapabilityId, ChannelBinding, FeatureRef, ObjectDescriptor, ObjectDigest, OperationId,
    PrincipalId, ProtocolVersion, PublicationReservationId, ResourceId,
};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::publisher::{
    decode_authority, decode_target, encode_authority, encode_target, protocol_component,
};
use super::tree::{
    decode_descriptor, decode_feature, encode_descriptor, encode_feature, encode_slice,
    exact_bytes, semantics,
};

/// Encodes the complete v1 admission preimage without its derived commitment.
#[must_use]
pub fn encode_publisher_admission_request_v1(request: &PublisherAdmissionRequestV1) -> Vec<u8> {
    let fields = request.plan().fields();
    let mut encoder = encode_prefix(
        request.capability(),
        request.cache_resource(),
        request.challenge(),
        fields.protocol_version,
        &fields.target,
    );
    encode_claim(
        &mut encoder,
        ClaimFields {
            holder: &fields.request.holder,
            channel: &fields.request.channel,
            operation: &fields.request.operation,
            reservation: &fields.request.reservation,
            content: &fields.request.content,
            source_authorization: &fields.request.source_authorization,
            maximum_bytes: fields.request.maximum_bytes,
        },
    );
    encode_suffix(
        encoder,
        &fields.authority,
        fields.issued_seconds,
        fields.expires_seconds,
        &fields.required_features,
    )
}

/// Encodes bounded draft fields before the commitment exists.
///
/// The model constructor bounds the features before calling this function and
/// validates the resulting plan before exposing a public request.
pub(crate) fn encode_publisher_admission_draft_v1(
    draft: &PublisherAdmissionRequestDraftV1,
) -> Vec<u8> {
    let mut encoder = encode_prefix(
        draft.capability,
        draft.cache_resource,
        draft.challenge,
        draft.protocol_version,
        &draft.target,
    );
    encode_claim(
        &mut encoder,
        ClaimFields {
            holder: &draft.claim.holder,
            channel: &draft.claim.channel,
            operation: &draft.claim.operation,
            reservation: &draft.claim.reservation,
            content: &draft.claim.content,
            source_authorization: &draft.claim.source_authorization,
            maximum_bytes: draft.claim.maximum_bytes,
        },
    );
    encode_suffix(
        encoder,
        &draft.authority,
        draft.issued_seconds,
        draft.expires_seconds,
        &draft.required_features,
    )
}

fn encode_prefix(
    capability: CapabilityId,
    cache_resource: ResourceId,
    challenge: PublisherChallengeV1,
    protocol_version: ProtocolVersion,
    target: &PublisherTarget,
) -> Encoder {
    let mut encoder = Encoder::new();
    encoder.array(11);
    encoder.unsigned(1);
    encoder.bytes(capability.as_bytes());
    encoder.bytes(cache_resource.as_bytes());
    encoder.bytes(challenge.as_bytes());
    encoder.array(2);
    encoder.unsigned(u64::from(protocol_version.major()));
    encoder.unsigned(u64::from(protocol_version.minor()));
    encode_target(&mut encoder, target);
    encoder
}

// Borrows either a draft claim or the validated plan's request without copying
// descriptor strings or required-feature vectors, or encoding its commitment.
struct ClaimFields<'a> {
    holder: &'a PrincipalId,
    channel: &'a ChannelBinding,
    operation: &'a OperationId,
    reservation: &'a PublicationReservationId,
    content: &'a ObjectDescriptor,
    source_authorization: &'a ObjectDigest,
    maximum_bytes: u64,
}

fn encode_claim(encoder: &mut Encoder, claim: ClaimFields<'_>) {
    encoder.array(7);
    encoder.bytes(claim.holder.as_bytes());
    encoder.bytes(claim.channel.as_bytes());
    encoder.bytes(claim.operation.as_bytes());
    encoder.bytes(claim.reservation.as_bytes());
    encode_descriptor(encoder, claim.content);
    encoder.bytes(claim.source_authorization.as_bytes());
    encoder.unsigned(claim.maximum_bytes);
}

fn encode_suffix(
    mut encoder: Encoder,
    authority: &PublisherAuthorityBindings,
    issued_seconds: i64,
    expires_seconds: i64,
    required_features: &[FeatureRef],
) -> Vec<u8> {
    encode_authority(&mut encoder, authority);
    encoder.signed(issued_seconds);
    encoder.signed(expires_seconds);
    encode_slice(&mut encoder, required_features, encode_feature);
    encoder.finish()
}

/// Decodes a bounded canonical v1 admission request and reconstructs its commitment.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for noncanonical encoding, incorrect framing or
/// scalar widths, trailing bytes, caller-limit or 32 KiB violations, more than 64 features,
/// or invalid/unsupported request semantics. No supplied field is authenticated.
pub fn decode_publisher_admission_request_v1(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<PublisherAdmissionRequestV1, CanonicalCborError> {
    let limits = DecodeLimits {
        maximum_bytes: limits
            .maximum_bytes
            .min(crate::publisher::MAXIMUM_PUBLISHER_ADMISSION_REQUEST_BYTES),
        ..limits
    };
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(11)?;
    decoder.exact("publisher admission request version", 1)?;
    let capability = CapabilityId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let cache_resource = ResourceId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let challenge = PublisherChallengeV1::from_bytes(exact_bytes(&mut decoder, 32)?)
        .map_err(|error| semantics("publisher challenge", error))?;
    decoder.array(2)?;
    let major = protocol_component(&mut decoder)?;
    let minor = protocol_component(&mut decoder)?;
    let target = decode_target(&mut decoder)?;
    decoder.array(7)?;
    let claim = PublisherAdmissionClaimV1 {
        holder: PrincipalId::from_bytes(exact_bytes(&mut decoder, 16)?),
        channel: ChannelBinding::new(exact_bytes(&mut decoder, 32)?),
        operation: OperationId::from_bytes(exact_bytes(&mut decoder, 16)?),
        reservation: PublicationReservationId::from_bytes(exact_bytes(&mut decoder, 16)?),
        content: decode_descriptor(&mut decoder)?,
        source_authorization: ObjectDigest::from_bytes(exact_bytes(&mut decoder, 32)?),
        maximum_bytes: decoder.unsigned()?,
    };
    let authority = decode_authority(&mut decoder)?;
    let issued_seconds = decoder.signed()?;
    let expires_seconds = decoder.signed()?;

    let feature_offset = decoder.position();
    let feature_count = decoder.array_len()?;
    if feature_count > 64 {
        return Err(CanonicalCborError::CollectionTooLarge {
            offset: feature_offset,
        });
    }
    let mut required_features = Vec::with_capacity(feature_count);
    for _ in 0..feature_count {
        required_features.push(decode_feature(&mut decoder)?);
    }
    decoder.finish()?;

    PublisherAdmissionRequestV1::new(PublisherAdmissionRequestDraftV1 {
        capability,
        cache_resource,
        challenge,
        protocol_version: ProtocolVersion::new(major, minor),
        target,
        claim,
        authority,
        issued_seconds,
        expires_seconds,
        required_features,
    })
    .map_err(|error| semantics("publisher admission request", error))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "Invalid fixtures and assertions intentionally panic."
)]
mod tests {
    use super::*;
    use crate::model::{CacheDomain, CacheDomainKind};
    use crate::{
        CacheDomainId, MediaType, NodeId, ProjectId, PublisherInstanceId,
        PublisherRequestCommitment, RevocationScopeId,
    };

    fn draft() -> PublisherAdmissionRequestDraftV1 {
        PublisherAdmissionRequestDraftV1 {
            capability: CapabilityId::from_bytes([16; 16]),
            cache_resource: ResourceId::from_bytes([17; 16]),
            challenge: PublisherChallengeV1::from_bytes([18; 32]).unwrap(),
            protocol_version: ProtocolVersion::new(1, 0),
            target: PublisherTarget {
                principal: PrincipalId::from_bytes([1; 16]),
                instance: PublisherInstanceId::from_bytes([2; 16]),
                node: NodeId::from_bytes([3; 16]),
                project: ProjectId::from_bytes([4; 16]),
                cache_domain: CacheDomain::new(
                    CacheDomainKind::Project,
                    CacheDomainId::from_bytes([5; 16]),
                ),
                isolation_policy: ObjectDigest::from_bytes([6; 32]),
            },
            claim: PublisherAdmissionClaimV1 {
                holder: PrincipalId::from_bytes([7; 16]),
                channel: ChannelBinding::new([8; 32]),
                operation: OperationId::from_bytes([9; 16]),
                reservation: PublicationReservationId::from_bytes([10; 16]),
                content: ObjectDescriptor::new(
                    MediaType::new("application/vnd.aos.sandbox.content.v1").unwrap(),
                    ObjectDigest::from_bytes([11; 32]),
                    3,
                ),
                source_authorization: ObjectDigest::from_bytes([12; 32]),
                maximum_bytes: 4096,
            },
            authority: PublisherAuthorityBindings {
                policy: ObjectDigest::from_bytes([14; 32]),
                policy_generation: 1,
                controller_generation: 2,
                revocation_scope: RevocationScopeId::from_bytes([15; 16]),
                revocation_generation: 3,
                root_registry_generation: 4,
            },
            issued_seconds: -1,
            expires_seconds: 300,
            required_features: Vec::new(),
        }
    }

    fn wire() -> Vec<u8> {
        encode_publisher_admission_draft_v1(&draft())
    }

    #[test]
    fn complete_golden_preimage_matches_both_encoders_and_reconstructed_commitment() {
        let expected = hex::decode(format!(
            concat!(
                "8b0150{}50{}5820{}8201008650{}50{}50{}50{}820150{}5820{}",
                "8750{}5820{}50{}50{}847826{}015820{}035820{}191000",
                "865820{}010250{}03042019012c80"
            ),
            "10".repeat(16),
            "11".repeat(16),
            "12".repeat(32),
            "01".repeat(16),
            "02".repeat(16),
            "03".repeat(16),
            "04".repeat(16),
            "05".repeat(16),
            "06".repeat(32),
            "07".repeat(16),
            "08".repeat(32),
            "09".repeat(16),
            "0a".repeat(16),
            "6170706c69636174696f6e2f766e642e616f732e73616e64626f782e636f6e74656e742e7631",
            "0b".repeat(32),
            "0c".repeat(32),
            "0e".repeat(32),
            "0f".repeat(16),
        ))
        .unwrap();
        let request = PublisherAdmissionRequestV1::new(draft()).unwrap();
        assert_eq!(wire(), expected);
        assert_eq!(encode_publisher_admission_request_v1(&request), expected);
        assert_eq!(
            decode_publisher_admission_request_v1(&expected, DecodeLimits::default()).unwrap(),
            request
        );
        assert_eq!(
            request.plan().fields().request.commitment,
            PublisherRequestCommitment::for_canonical_bytes(&expected)
        );
    }

    #[test]
    fn truncation_trailing_nonshortest_and_extra_reserved_field_fail_closed() {
        let canonical = wire();
        for length in 0..canonical.len() {
            assert!(
                decode_publisher_admission_request_v1(
                    &canonical[..length],
                    DecodeLimits::default()
                )
                .is_err(),
                "accepted prefix {length}"
            );
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(decode_publisher_admission_request_v1(&trailing, DecodeLimits::default()).is_err());
        let mut nonshortest = canonical.clone();
        nonshortest.splice(1..2, [0x18, 1]);
        assert!(matches!(
            decode_publisher_admission_request_v1(&nonshortest, DecodeLimits::default()),
            Err(CanonicalCborError::NonShortestArgument { .. })
        ));
        trailing[0] = 0x8c;
        assert!(decode_publisher_admission_request_v1(&trailing, DecodeLimits::default()).is_err());
    }

    #[test]
    fn sentinel_width_protocol_and_schema_rejections() {
        let canonical = wire();
        for (start, length) in [(3, 16), (20, 16), (38, 32)] {
            let mut zero = canonical.clone();
            zero[start..start + length].fill(0);
            assert!(decode_publisher_admission_request_v1(&zero, DecodeLimits::default()).is_err());
        }
        // Header positions are fixed by the independent full golden vector.
        for (offset, replacement) in [
            (0, 0x8a),
            (1, 2),
            (2, 0x4f),
            (19, 0x4f),
            (37, 31),
            (70, 0x83),
            (71, 2),
        ] {
            let mut invalid = canonical.clone();
            invalid[offset] = replacement;
            assert!(
                decode_publisher_admission_request_v1(&invalid, DecodeLimits::default()).is_err(),
                "accepted mutation at {offset}"
            );
        }
        let mut wide = canonical;
        wide.splice(71..72, [0x1a, 0, 1, 0, 0]);
        assert!(decode_publisher_admission_request_v1(&wide, DecodeLimits::default()).is_err());
    }

    #[test]
    fn semantic_features_and_hard_cardinality_limit_are_enforced() {
        let mut fields = draft();
        fields.claim.maximum_bytes = 2;
        assert!(
            decode_publisher_admission_request_v1(
                &encode_publisher_admission_draft_v1(&fields),
                DecodeLimits::default()
            )
            .is_err()
        );
        let known = FeatureRef::new("aos.sandbox.storage.portable", 1, 0).unwrap();
        for features in [
            vec![known.clone(), known.clone()],
            vec![FeatureRef::new("aos.test.unknown", 1, 0).unwrap()],
        ] {
            let mut fields = draft();
            fields.required_features = features;
            assert!(
                decode_publisher_admission_request_v1(
                    &encode_publisher_admission_draft_v1(&fields),
                    DecodeLimits::default()
                )
                .is_err()
            );
        }
        let mut fields = draft();
        fields.required_features = vec![known; 65];
        assert!(matches!(
            decode_publisher_admission_request_v1(
                &encode_publisher_admission_draft_v1(&fields),
                DecodeLimits::default()
            ),
            Err(CanonicalCborError::CollectionTooLarge { .. })
        ));
    }

    #[test]
    fn caller_resource_limits_remain_independent_of_schema_limits() {
        let canonical = wire();
        for limits in [
            DecodeLimits {
                maximum_bytes: canonical.len() - 1,
                ..DecodeLimits::default()
            },
            DecodeLimits {
                maximum_collection_items: 10,
                ..DecodeLimits::default()
            },
            DecodeLimits {
                maximum_total_items: 10,
                ..DecodeLimits::default()
            },
            DecodeLimits {
                maximum_byte_string_bytes: 31,
                ..DecodeLimits::default()
            },
            DecodeLimits {
                maximum_text_bytes: 37,
                ..DecodeLimits::default()
            },
            DecodeLimits {
                maximum_depth: 1,
                ..DecodeLimits::default()
            },
        ] {
            assert!(decode_publisher_admission_request_v1(&canonical, limits).is_err());
        }
    }

    #[test]
    fn signed_extremes_and_supported_features_round_trip() {
        let mut fields = draft();
        fields.issued_seconds = i64::MIN;
        fields.expires_seconds = i64::MAX;
        fields.required_features = vec![
            FeatureRef::new("aos.sandbox.identity.posix32", 1, 0).unwrap(),
            FeatureRef::new("aos.sandbox.storage.portable", 1, 0).unwrap(),
        ];
        let request = PublisherAdmissionRequestV1::new(fields).unwrap();
        let encoded = encode_publisher_admission_request_v1(&request);
        assert_eq!(
            decode_publisher_admission_request_v1(&encoded, DecodeLimits::default()).unwrap(),
            request
        );
    }
}

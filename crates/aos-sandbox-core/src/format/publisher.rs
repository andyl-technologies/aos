//! Canonical project-domain publisher-plan encoding, independent of assignments.
//!
//! The exact v1 schema uses definite-length arrays and the common descriptor
//! and feature encodings. Identities are 16-byte strings; commitments and channel
//! bindings are 32-byte strings. Times are signed Unix seconds.
//!
//! ```text
//! [1, [protocol_major, protocol_minor],
//!  [publisher_principal, publisher_instance, node, project,
//!   [1, cache_domain_id], isolation_policy],
//!  [holder, channel, operation, reservation,
//!   [content_media_type, 1, content_sha256, content_size],
//!   source_authorization, request_commitment, maximum_bytes],
//!  [policy, policy_generation, controller_generation, revocation_scope,
//!   revocation_generation, root_registry_generation],
//!  issued_seconds, expires_seconds,
//!  [[feature_namespace, feature_major, feature_minor], ...]]
//! ```
//!
//! The registered publisher media type selects the protocol domain; no broker
//! audience or sandbox assignment is encoded. Decoding yields a structurally
//! validated but inert plan, not online admission or a completion permit.

use crate::model::{CacheDomain, CacheDomainKind};
use crate::publisher::{
    PublisherAuthorityBindings, PublisherDomainPlan, PublisherDomainPlanDraft, PublisherRequest,
    PublisherRequestCommitment, PublisherTarget,
};
use crate::{
    CacheDomainId, ChannelBinding, NodeId, ObjectDigest, OperationId, PrincipalId, ProjectId,
    ProtocolVersion, PublicationReservationId, PublisherInstanceId, RevocationScopeId,
};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{
    decode_descriptor, decode_feature, encode_descriptor, encode_feature, encode_slice,
    exact_bytes, semantics,
};

/// Encodes one structurally validated publisher-domain plan as canonical v1 CBOR.
#[must_use]
pub fn encode_publisher_domain_plan(plan: &PublisherDomainPlan) -> Vec<u8> {
    encode_fields(plan.fields())
}

fn encode_fields(fields: &PublisherDomainPlanDraft) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(8);
    encoder.unsigned(1);
    encoder.array(2);
    encoder.unsigned(u64::from(fields.protocol_version.major()));
    encoder.unsigned(u64::from(fields.protocol_version.minor()));
    encode_target(&mut encoder, &fields.target);
    encode_request(&mut encoder, &fields.request);
    encode_authority(&mut encoder, &fields.authority);
    encoder.signed(fields.issued_seconds);
    encoder.signed(fields.expires_seconds);
    encode_slice(&mut encoder, &fields.required_features, encode_feature);
    encoder.finish()
}

/// Decodes one bounded, canonical publisher-domain plan without granting authority.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for noncanonical CBOR, incorrect array lengths
/// or scalar widths, trailing bytes, caller-limit violations, more than 64
/// features, or invalid/unsupported publisher model semantics. No signature,
/// source authorization, currentness or completion permission is inferred.
pub fn decode_publisher_domain_plan(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<PublisherDomainPlan, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(8)?;
    decoder.exact("publisher plan version", 1)?;
    decoder.array(2)?;
    let major = protocol_component(&mut decoder)?;
    let minor = protocol_component(&mut decoder)?;
    let target = decode_target(&mut decoder)?;
    let request = decode_request(&mut decoder)?;
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

    PublisherDomainPlan::new(PublisherDomainPlanDraft {
        protocol_version: ProtocolVersion::new(major, minor),
        target,
        request,
        authority,
        issued_seconds,
        expires_seconds,
        required_features,
    })
    .map_err(|error| semantics("publisher domain plan", error))
}

pub(super) fn protocol_component(decoder: &mut Decoder<'_>) -> Result<u16, CanonicalCborError> {
    u16::try_from(decoder.unsigned()?)
        .map_err(|_| semantics("publisher protocol", "version component exceeds u16"))
}

pub(super) fn encode_target(encoder: &mut Encoder, target: &PublisherTarget) {
    encoder.array(6);
    encoder.bytes(target.principal.as_bytes());
    encoder.bytes(target.instance.as_bytes());
    encoder.bytes(target.node.as_bytes());
    encoder.bytes(target.project.as_bytes());
    encoder.array(2);
    // A validated v1 target is always a project disclosure domain.
    encoder.unsigned(1);
    encoder.bytes(target.cache_domain.domain_id().as_bytes());
    encoder.bytes(target.isolation_policy.as_bytes());
}

pub(super) fn decode_target(
    decoder: &mut Decoder<'_>,
) -> Result<PublisherTarget, CanonicalCborError> {
    decoder.array(6)?;
    let principal = PrincipalId::from_bytes(exact_bytes(decoder, 16)?);
    let instance = PublisherInstanceId::from_bytes(exact_bytes(decoder, 16)?);
    let node = NodeId::from_bytes(exact_bytes(decoder, 16)?);
    let project = ProjectId::from_bytes(exact_bytes(decoder, 16)?);
    decoder.array(2)?;
    decoder.exact("publisher cache domain kind", 1)?;
    let domain = CacheDomainId::from_bytes(exact_bytes(decoder, 16)?);
    let isolation_policy = ObjectDigest::from_bytes(exact_bytes(decoder, 32)?);
    Ok(PublisherTarget {
        principal,
        instance,
        node,
        project,
        cache_domain: CacheDomain::new(CacheDomainKind::Project, domain),
        isolation_policy,
    })
}

fn encode_request(encoder: &mut Encoder, request: &PublisherRequest) {
    encoder.array(8);
    encoder.bytes(request.holder.as_bytes());
    encoder.bytes(request.channel.as_bytes());
    encoder.bytes(request.operation.as_bytes());
    encoder.bytes(request.reservation.as_bytes());
    encode_descriptor(encoder, &request.content);
    encoder.bytes(request.source_authorization.as_bytes());
    encoder.bytes(request.commitment.digest().as_bytes());
    encoder.unsigned(request.maximum_bytes);
}

fn decode_request(decoder: &mut Decoder<'_>) -> Result<PublisherRequest, CanonicalCborError> {
    decoder.array(8)?;
    Ok(PublisherRequest {
        holder: PrincipalId::from_bytes(exact_bytes(decoder, 16)?),
        channel: ChannelBinding::new(exact_bytes(decoder, 32)?),
        operation: OperationId::from_bytes(exact_bytes(decoder, 16)?),
        reservation: PublicationReservationId::from_bytes(exact_bytes(decoder, 16)?),
        content: decode_descriptor(decoder)?,
        source_authorization: ObjectDigest::from_bytes(exact_bytes(decoder, 32)?),
        commitment: PublisherRequestCommitment::from_digest(ObjectDigest::from_bytes(exact_bytes(
            decoder, 32,
        )?))
        .map_err(|error| semantics("publisher request commitment", error))?,
        maximum_bytes: decoder.unsigned()?,
    })
}

pub(super) fn encode_authority(encoder: &mut Encoder, authority: &PublisherAuthorityBindings) {
    encoder.array(6);
    encoder.bytes(authority.policy.as_bytes());
    encoder.unsigned(authority.policy_generation);
    encoder.unsigned(authority.controller_generation);
    encoder.bytes(authority.revocation_scope.as_bytes());
    encoder.unsigned(authority.revocation_generation);
    encoder.unsigned(authority.root_registry_generation);
}

pub(super) fn decode_authority(
    decoder: &mut Decoder<'_>,
) -> Result<PublisherAuthorityBindings, CanonicalCborError> {
    decoder.array(6)?;
    Ok(PublisherAuthorityBindings {
        policy: ObjectDigest::from_bytes(exact_bytes(decoder, 32)?),
        policy_generation: decoder.unsigned()?,
        controller_generation: decoder.unsigned()?,
        revocation_scope: RevocationScopeId::from_bytes(exact_bytes(decoder, 16)?),
        revocation_generation: decoder.unsigned()?,
        root_registry_generation: decoder.unsigned()?,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "Fixture construction and failed assertions intentionally panic in these tests."
)]
mod tests {
    use super::*;
    use crate::{FeatureRef, MediaType, ObjectDescriptor};

    fn draft() -> PublisherDomainPlanDraft {
        PublisherDomainPlanDraft {
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
            request: PublisherRequest {
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
                commitment: PublisherRequestCommitment::from_digest(ObjectDigest::from_bytes(
                    [13; 32],
                ))
                .unwrap(),
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

    fn feature(name: &str) -> FeatureRef {
        FeatureRef::new(name.to_owned(), 1, 0).unwrap()
    }

    #[test]
    fn exact_v1_wire_matches_independent_golden_and_round_trips() {
        let plan = PublisherDomainPlan::new(draft()).unwrap();
        // Literal structural headers fix all array lengths, widths, ordering,
        // signed-time encoding and the common four-field descriptor framing.
        let expected_hex = format!(
            concat!(
                "88018201008650{}50{}50{}50{}820150{}5820{}",
                "8850{}5820{}50{}50{}847826{}015820{}035820{}5820{}191000",
                "865820{}010250{}03042019012c80"
            ),
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
            hex::encode(b"application/vnd.aos.sandbox.content.v1"),
            "0b".repeat(32),
            "0c".repeat(32),
            "0d".repeat(32),
            "0e".repeat(32),
            "0f".repeat(16),
        );
        let expected = hex::decode(expected_hex).unwrap();
        assert_eq!(encode_publisher_domain_plan(&plan), expected);
        assert_eq!(
            decode_publisher_domain_plan(&expected, DecodeLimits::default()).unwrap(),
            plan
        );
    }

    #[test]
    fn signed_extremes_and_supported_features_round_trip() {
        let mut fields = draft();
        fields.issued_seconds = i64::MIN;
        fields.expires_seconds = i64::MAX;
        fields.required_features = vec![
            feature("aos.sandbox.identity.posix32"),
            feature("aos.sandbox.storage.portable"),
        ];
        let plan = PublisherDomainPlan::new(fields).unwrap();
        let wire = encode_publisher_domain_plan(&plan);
        assert_eq!(
            decode_publisher_domain_plan(&wire, DecodeLimits::default()).unwrap(),
            plan
        );
    }

    #[test]
    fn truncation_trailing_bytes_and_noncanonical_version_fail_closed() {
        let wire = encode_fields(&draft());
        for end in 0..wire.len() {
            assert!(
                decode_publisher_domain_plan(&wire[..end], DecodeLimits::default()).is_err(),
                "truncation at {end}"
            );
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(decode_publisher_domain_plan(&trailing, DecodeLimits::default()).is_err());

        let mut nonshortest = wire.clone();
        nonshortest.splice(1..2, [0x18, 1]);
        assert!(matches!(
            decode_publisher_domain_plan(&nonshortest, DecodeLimits::default()),
            Err(CanonicalCborError::NonShortestArgument { .. })
        ));
        let mut version = wire;
        version[1] = 2;
        assert!(decode_publisher_domain_plan(&version, DecodeLimits::default()).is_err());
    }

    #[test]
    fn wrong_array_shapes_domain_kind_and_scalar_widths_are_rejected() {
        let wire = encode_fields(&draft());
        for (offset, replacement) in [(0, 0x87), (2, 0x81), (5, 0x85)] {
            let mut changed = wire.clone();
            changed[offset] = replacement;
            assert!(decode_publisher_domain_plan(&changed, DecodeLimits::default()).is_err());
        }
        let mut wide_version = wire.clone();
        wide_version.splice(3..4, [0x1a, 0, 1, 0, 0]);
        assert!(decode_publisher_domain_plan(&wide_version, DecodeLimits::default()).is_err());

        let mut wrong_identity_width = wire.clone();
        wrong_identity_width[6] = 0x4f;
        wrong_identity_width.remove(7);
        assert!(
            decode_publisher_domain_plan(&wrong_identity_width, DecodeLimits::default()).is_err()
        );

        // The target has four identities, each a one-byte length plus16 bytes.
        let domain_kind_offset = 6 + 4 * 17 + 1;
        for kind in [0, 2, 3, 4] {
            let mut wrong_domain = wire.clone();
            wrong_domain[domain_kind_offset] = kind;
            assert!(decode_publisher_domain_plan(&wrong_domain, DecodeLimits::default()).is_err());
        }
    }

    #[test]
    fn semantic_model_validation_is_not_bypassed_by_decoding() {
        let mutations: [fn(&mut PublisherDomainPlanDraft); 8] = [
            |fields| fields.target.principal = PrincipalId::from_bytes([0; 16]),
            |fields| fields.request.channel = ChannelBinding::new([0; 32]),
            |fields| fields.request.source_authorization = ObjectDigest::from_bytes([0; 32]),
            |fields| fields.authority.controller_generation = 0,
            |fields| fields.expires_seconds = fields.issued_seconds,
            |fields| fields.request.maximum_bytes = 2,
            |fields| fields.request.maximum_bytes = u64::MAX,
            |fields| fields.protocol_version = ProtocolVersion::new(2, 0),
        ];
        for (case, mutate) in mutations.into_iter().enumerate() {
            let mut fields = draft();
            mutate(&mut fields);
            assert!(
                decode_publisher_domain_plan(&encode_fields(&fields), DecodeLimits::default())
                    .is_err(),
                "semantic mutation {case}"
            );
        }
        let mut fields = draft();
        fields.request.content = ObjectDescriptor::new(
            MediaType::new("application/octet-stream").unwrap(),
            ObjectDigest::from_bytes([11; 32]),
            3,
        );
        assert!(
            decode_publisher_domain_plan(&encode_fields(&fields), DecodeLimits::default()).is_err()
        );
    }

    #[test]
    fn features_are_known_strictly_ordered_and_bounded_before_allocation() {
        let known = feature("aos.sandbox.identity.posix32");
        for features in [
            vec![known.clone(), known.clone()],
            vec![feature("aos.sandbox.storage.portable"), known.clone()],
            vec![feature("example.unknown")],
        ] {
            let mut fields = draft();
            fields.required_features = features;
            assert!(
                decode_publisher_domain_plan(&encode_fields(&fields), DecodeLimits::default())
                    .is_err()
            );
        }
        let mut fields = draft();
        fields.required_features = vec![known; 65];
        assert!(matches!(
            decode_publisher_domain_plan(&encode_fields(&fields), DecodeLimits::default()),
            Err(CanonicalCborError::CollectionTooLarge { .. })
        ));
    }

    #[test]
    fn caller_resource_limits_are_enforced() {
        let wire = encode_fields(&draft());
        for limits in [
            DecodeLimits {
                maximum_bytes: wire.len() - 1,
                ..DecodeLimits::default()
            },
            DecodeLimits {
                maximum_collection_items: 7,
                ..DecodeLimits::default()
            },
            DecodeLimits {
                maximum_total_items: 1,
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
            assert!(decode_publisher_domain_plan(&wire, limits).is_err());
        }
    }
}

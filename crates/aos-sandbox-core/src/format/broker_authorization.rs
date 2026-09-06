//! Canonical codec for audience-specific broker authorization plans.

use crate::broker_authorization::{
    BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, BrokerGrantTarget,
    BrokerResourceHandle, BrokerVerb,
};
use crate::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NodeId, ObjectDigest, ProtocolId,
    ProtocolVersion, RevocationScopeId, SandboxId,
};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{decode_feature, encode_feature, encode_slice, exact_bytes, semantics};
use super::trust::{decode_key_reference, encode_key_reference};

/// Encodes a broker authorization plan in exact portable v1 CBOR.
#[must_use]
pub fn encode_broker_authorization_plan(plan: &BrokerAuthorizationPlan) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(14);
    encoder.unsigned(1);
    encoder.unsigned(audience_code(plan.audience()));
    encoder.unsigned(protocol_code(plan.protocol()));
    encoder.unsigned(u64::from(plan.protocol_version().major()));
    encoder.unsigned(u64::from(plan.protocol_version().minor()));
    encode_assignment(&mut encoder, plan.assignment());
    encoder.bytes(plan.node().as_bytes());
    encode_key_reference(&mut encoder, plan.ownership_authority());
    encode_slice(&mut encoder, plan.grants(), encode_grant);
    encoder.bytes(plan.policy_commitment().as_bytes());
    encoder.bytes(plan.revocation_scope().as_bytes());
    encoder.signed(plan.issued_seconds());
    encoder.signed(plan.expires_seconds());
    encode_slice(&mut encoder, plan.required_features(), encode_feature);
    encoder.finish()
}

/// Decodes one exact canonical broker authorization plan.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for deterministic-CBOR violations, unknown
/// audience/version semantics, invalid bounds, unknown required features, or a
/// noncanonical grant/feature set.
pub fn decode_broker_authorization_plan(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<BrokerAuthorizationPlan, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(14)?;
    decoder.exact("broker authorization plan version", 1)?;
    let audience = decode_audience(&mut decoder)?;
    let protocol = decode_protocol(&mut decoder)?;
    let protocol_major = u16::try_from(decoder.unsigned()?)
        .map_err(|_| semantics("broker protocol", "major exceeds its schema width"))?;
    let protocol_minor = u16::try_from(decoder.unsigned()?)
        .map_err(|_| semantics("broker protocol", "minor exceeds its schema width"))?;
    if protocol != audience.protocol() {
        return Err(CanonicalCborError::InvalidSemantics {
            object: "broker protocol",
            message: "protocol does not match audience".to_owned(),
        });
    }
    let assignment = decode_assignment(&mut decoder)?;
    let node = NodeId::from_bytes(exact_bytes::<16>(&mut decoder, 16)?);
    let ownership_authority = decode_key_reference(&mut decoder)?;
    let grants = decode_bounded_vec(&mut decoder, 1_024, decode_grant)?;
    let policy_commitment = ObjectDigest::from_bytes(exact_bytes::<32>(&mut decoder, 32)?);
    let revocation_scope = RevocationScopeId::from_bytes(exact_bytes::<16>(&mut decoder, 16)?);
    let issued_seconds = decoder.signed()?;
    let expires_seconds = decoder.signed()?;
    let required_features = decode_bounded_vec(&mut decoder, 64, decode_feature)?;
    decoder.finish()?;

    BrokerAuthorizationPlan::new(
        audience,
        protocol,
        ProtocolVersion::new(protocol_major, protocol_minor),
        assignment,
        node,
        ownership_authority,
        grants,
        policy_commitment,
        revocation_scope,
        issued_seconds,
        expires_seconds,
        required_features,
    )
    .map_err(|error| semantics("broker authorization plan", error))
}

fn encode_assignment(encoder: &mut Encoder, assignment: BrokerAssignment) {
    encoder.array(5);
    encoder.bytes(assignment.sandbox().as_bytes());
    encoder.bytes(assignment.incarnation().as_bytes());
    encoder.unsigned(assignment.epoch().get());
    encoder.unsigned(assignment.desired_generation().get());
    encoder.bytes(assignment.digest().as_bytes());
}

fn decode_assignment(decoder: &mut Decoder<'_>) -> Result<BrokerAssignment, CanonicalCborError> {
    decoder.array(5)?;
    BrokerAssignment::new(
        SandboxId::from_bytes(exact_bytes::<16>(decoder, 16)?),
        IncarnationId::from_bytes(exact_bytes::<16>(decoder, 16)?),
        AssignmentEpoch::new(decoder.unsigned()?),
        DesiredGeneration::new(decoder.unsigned()?),
        ObjectDigest::from_bytes(exact_bytes::<32>(decoder, 32)?),
    )
    .map_err(|error| semantics("broker assignment", error))
}

fn encode_grant(encoder: &mut Encoder, grant: &BrokerGrant) {
    encoder.array(5);
    encoder.unsigned(u64::from(grant.verb().get()));
    match grant.target() {
        BrokerGrantTarget::Assignment => {
            encoder.array(1);
            encoder.unsigned(0);
        }
        BrokerGrantTarget::Resource(resource) => {
            encoder.array(2);
            encoder.unsigned(1);
            encoder.bytes(resource.as_bytes());
        }
        BrokerGrantTarget::ResourcePair {
            previous,
            successor,
        } => {
            encoder.array(3);
            encoder.unsigned(2);
            encoder.bytes(previous.as_bytes());
            encoder.bytes(successor.as_bytes());
        }
    }
    encoder.bytes(grant.argument_commitment().digest().as_bytes());
    encoder.unsigned(u64::from(grant.maximum_request_bytes()));
    encoder.unsigned(u64::from(grant.maximum_descriptors()));
}

fn decode_grant(decoder: &mut Decoder<'_>) -> Result<BrokerGrant, CanonicalCborError> {
    decoder.array(5)?;
    let verb_value = decode_u32(decoder, "broker verb")?;
    let verb =
        BrokerVerb::from_code(verb_value).map_err(|error| semantics("broker grant", error))?;
    let target = decode_target(decoder)?;
    let argument_commitment = crate::BrokerArgumentCommitment::from_digest(
        ObjectDigest::from_bytes(exact_bytes::<32>(decoder, 32)?),
    )
    .map_err(|error| semantics("broker argument commitment", error))?;
    let maximum_request_bytes = decode_u32(decoder, "broker request byte limit")?;
    let maximum_descriptors = decode_u16(decoder, "broker descriptor limit")?;
    BrokerGrant::new(
        verb,
        target,
        argument_commitment,
        maximum_request_bytes,
        maximum_descriptors,
    )
    .map_err(|error| semantics("broker grant", error))
}

fn decode_target(decoder: &mut Decoder<'_>) -> Result<BrokerGrantTarget, CanonicalCborError> {
    let length = decoder.array_len()?;
    let offset = decoder.position();
    let kind = decoder.unsigned()?;
    match (kind, length) {
        (0, 1) => Ok(BrokerGrantTarget::Assignment),
        (1, 2) => BrokerResourceHandle::from_bytes(exact_bytes::<32>(decoder, 32)?)
            .map(BrokerGrantTarget::Resource)
            .map_err(|error| semantics("broker grant target", error)),
        (2, 3) => {
            let previous = BrokerResourceHandle::from_bytes(exact_bytes::<32>(decoder, 32)?)
                .map_err(|error| semantics("broker grant target", error))?;
            let successor = BrokerResourceHandle::from_bytes(exact_bytes::<32>(decoder, 32)?)
                .map_err(|error| semantics("broker grant target", error))?;
            Ok(BrokerGrantTarget::ResourcePair {
                previous,
                successor,
            })
        }
        (0..=2, _) => Err(CanonicalCborError::InvalidSemantics {
            object: "broker grant target",
            message: "target discriminant has the wrong array shape".to_owned(),
        }),
        (value, _) => Err(CanonicalCborError::UnknownRegistryValue {
            registry: "broker grant target",
            value,
            offset,
        }),
    }
}

fn decode_bounded_vec<T>(
    decoder: &mut Decoder<'_>,
    maximum: usize,
    mut decode: impl FnMut(&mut Decoder<'_>) -> Result<T, CanonicalCborError>,
) -> Result<Vec<T>, CanonicalCborError> {
    let offset = decoder.position();
    let length = decoder.array_len()?;
    if length > maximum {
        return Err(CanonicalCborError::CollectionTooLarge { offset });
    }
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(decode(decoder)?);
    }
    Ok(values)
}

const fn audience_code(audience: BrokerAudience) -> u64 {
    match audience {
        BrokerAudience::Host => 0,
        BrokerAudience::Mount => 1,
        BrokerAudience::Storage => 2,
        BrokerAudience::Network => 3,
    }
}

fn decode_audience(decoder: &mut Decoder<'_>) -> Result<BrokerAudience, CanonicalCborError> {
    match decoder.closed("broker audience", 3)? {
        0 => Ok(BrokerAudience::Host),
        1 => Ok(BrokerAudience::Mount),
        2 => Ok(BrokerAudience::Storage),
        3 => Ok(BrokerAudience::Network),
        value => Err(CanonicalCborError::UnknownRegistryValue {
            registry: "broker audience",
            value,
            offset: decoder.position(),
        }),
    }
}

fn protocol_code(protocol: ProtocolId) -> u64 {
    match protocol {
        ProtocolId::HostBroker => 0,
        ProtocolId::MountBroker => 1,
        ProtocolId::StorageBroker => 2,
        ProtocolId::NetworkBroker => 3,
        ProtocolId::PublicApi
        | ProtocolId::PublisherAuthority
        | ProtocolId::CoordinatorNode
        | ProtocolId::OwnershipAuthority
        | ProtocolId::Guardian
        | ProtocolId::GuestAgent => unreachable!("broker plans use only broker protocols"),
    }
}

fn decode_protocol(decoder: &mut Decoder<'_>) -> Result<ProtocolId, CanonicalCborError> {
    match decoder.closed("broker protocol", 3)? {
        0 => Ok(ProtocolId::HostBroker),
        1 => Ok(ProtocolId::MountBroker),
        2 => Ok(ProtocolId::StorageBroker),
        3 => Ok(ProtocolId::NetworkBroker),
        value => Err(CanonicalCborError::UnknownRegistryValue {
            registry: "broker protocol",
            value,
            offset: decoder.position(),
        }),
    }
}

fn decode_u32(decoder: &mut Decoder<'_>, object: &'static str) -> Result<u32, CanonicalCborError> {
    u32::try_from(decoder.unsigned()?).map_err(|error| semantics(object, error))
}

fn decode_u16(decoder: &mut Decoder<'_>, object: &'static str) -> Result<u16, CanonicalCborError> {
    u16::try_from(decoder.unsigned()?).map_err(|error| semantics(object, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FeatureRef, InvalidBrokerAuthorizationPlan};

    const PLAN_HEX: &str = "8e01010101008550010101010101010101010101010101015002020202020202020202020202020202030458200505050505050505050505050505050505050505050505050505050505050505500a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a84696f776e657273686970015820090909090909090909090909090909090909090909090909090909090909090905818508810058200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b191000005820070707070707070707070707070707070707070707070707070707070707070750080808080808080808080808080808080a1481837825616f732e73616e64626f782e656e666f7263656d656e742e62726f6b65722d6c65646765720100";
    use crate::model::{KeyReference, KeyUsage, StableKeyId};

    fn ownership_authority() -> KeyReference {
        KeyReference::new(
            StableKeyId::new("ownership".to_owned())
                .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
            1,
            ObjectDigest::from_bytes([9; 32]),
            KeyUsage::OwnershipLease,
        )
    }

    #[test]
    fn publisher_registration_does_not_expand_broker_protocol_wire_codes() {
        let mut decoder = Decoder::new(&[4], DecodeLimits::default())
            .unwrap_or_else(|error| panic!("test broker protocol decoder failed: {error}"));
        assert!(matches!(
            decode_protocol(&mut decoder),
            Err(CanonicalCborError::UnknownRegistryValue { .. })
        ));
        let original = plan();
        assert!(matches!(
            BrokerAuthorizationPlan::new(
                original.audience(),
                ProtocolId::PublisherAuthority,
                ProtocolVersion::new(1, 0),
                original.assignment(),
                original.node(),
                original.ownership_authority().clone(),
                original.grants().to_vec(),
                original.policy_commitment(),
                original.revocation_scope(),
                original.issued_seconds(),
                original.expires_seconds(),
                original.required_features().to_vec(),
            ),
            Err(InvalidBrokerAuthorizationPlan::ProtocolAudienceMismatch)
        ));
    }

    fn plan() -> BrokerAuthorizationPlan {
        BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
            ProtocolVersion::new(1, 0),
            BrokerAssignment::new(
                SandboxId::from_bytes([1; 16]),
                IncarnationId::from_bytes([2; 16]),
                AssignmentEpoch::new(3),
                DesiredGeneration::new(4),
                ObjectDigest::from_bytes([5; 32]),
            )
            .unwrap_or_else(|error| panic!("test assignment failed: {error}")),
            NodeId::from_bytes([10; 16]),
            ownership_authority(),
            vec![
                BrokerGrant::new(
                    BrokerVerb::MountCreate,
                    BrokerGrantTarget::Assignment,
                    crate::BrokerArgumentCommitment::from_digest(ObjectDigest::from_bytes(
                        [11; 32],
                    ))
                    .unwrap_or_else(|error| panic!("test commitment failed: {error}")),
                    4_096,
                    0,
                )
                .unwrap_or_else(|error| panic!("test grant failed: {error}")),
            ],
            ObjectDigest::from_bytes([7; 32]),
            RevocationScopeId::from_bytes([8; 16]),
            10,
            20,
            vec![
                FeatureRef::new("aos.sandbox.enforcement.broker-ledger", 1, 0)
                    .unwrap_or_else(|error| panic!("test feature failed: {error}")),
            ],
        )
        .unwrap_or_else(|error| panic!("test plan failed: {error}"))
    }

    #[test]
    fn canonical_round_trip_is_exact() {
        let plan = plan();
        let bytes = encode_broker_authorization_plan(&plan);
        assert_eq!(hex::encode(&bytes), PLAN_HEX);
        assert_eq!(
            decode_broker_authorization_plan(&bytes, DecodeLimits::default()),
            Ok(plan)
        );
    }

    #[test]
    fn every_signed_broker_verb_round_trips_canonically() {
        let original = plan();
        let verbs = [
            BrokerVerb::HostLaunch,
            BrokerVerb::HostStop,
            BrokerVerb::HostFreeze,
            BrokerVerb::HostThaw,
            BrokerVerb::HostKill,
            BrokerVerb::HostObserve,
            BrokerVerb::HostInventory,
            BrokerVerb::MountCreate,
            BrokerVerb::MountInstall,
            BrokerVerb::MountReplace,
            BrokerVerb::MountDetach,
            BrokerVerb::MountRelease,
            BrokerVerb::MountInventorySummary,
            BrokerVerb::MountInventoryResources,
            BrokerVerb::StorageCreateWorkspace,
            BrokerVerb::StorageSnapshot,
            BrokerVerb::StorageHoldSnapshot,
            BrokerVerb::StorageReleaseHold,
            BrokerVerb::StorageClone,
            BrokerVerb::StorageSetQuota,
            BrokerVerb::StorageDestroy,
            BrokerVerb::StorageInventory,
            BrokerVerb::NetworkPrepare,
            BrokerVerb::NetworkArmLease,
            BrokerVerb::NetworkRenewLease,
            BrokerVerb::NetworkDisarm,
            BrokerVerb::NetworkDestroy,
            BrokerVerb::NetworkInventory,
        ];
        let resource = BrokerResourceHandle::from_bytes([30; 32])
            .unwrap_or_else(|error| panic!("test resource failed: {error}"));
        let successor = BrokerResourceHandle::from_bytes([31; 32])
            .unwrap_or_else(|error| panic!("test resource failed: {error}"));

        for verb in verbs {
            let audience = verb.audience();
            let target = match verb {
                BrokerVerb::HostLaunch
                | BrokerVerb::HostInventory
                | BrokerVerb::MountCreate
                | BrokerVerb::MountInventorySummary
                | BrokerVerb::MountInventoryResources
                | BrokerVerb::StorageCreateWorkspace
                | BrokerVerb::StorageInventory
                | BrokerVerb::NetworkPrepare
                | BrokerVerb::NetworkInventory => BrokerGrantTarget::Assignment,
                BrokerVerb::MountReplace => BrokerGrantTarget::ResourcePair {
                    previous: resource,
                    successor,
                },
                _ => BrokerGrantTarget::Resource(resource),
            };
            let candidate = BrokerAuthorizationPlan::new(
                audience,
                audience.protocol(),
                ProtocolVersion::new(1, 0),
                original.assignment(),
                original.node(),
                original.ownership_authority().clone(),
                vec![
                    BrokerGrant::new(
                        verb,
                        target,
                        crate::BrokerArgumentCommitment::from_digest(ObjectDigest::from_bytes(
                            [verb.get() as u8; 32],
                        ))
                        .unwrap_or_else(|error| panic!("test commitment failed: {error}")),
                        4_096,
                        0,
                    )
                    .unwrap_or_else(|error| panic!("test grant failed: {error}")),
                ],
                original.policy_commitment(),
                original.revocation_scope(),
                original.issued_seconds(),
                original.expires_seconds(),
                original.required_features().to_vec(),
            )
            .unwrap_or_else(|error| panic!("test plan failed: {error}"));
            let bytes = encode_broker_authorization_plan(&candidate);
            assert_eq!(
                decode_broker_authorization_plan(&bytes, DecodeLimits::default()),
                Ok(candidate)
            );
        }
    }

    #[test]
    fn audience_protocol_mismatch_and_unknown_codes_fail_closed() {
        let mut mismatch = encode_broker_authorization_plan(&plan());
        mismatch[2] = 2;
        assert!(matches!(
            decode_broker_authorization_plan(&mismatch, DecodeLimits::default()),
            Err(CanonicalCborError::InvalidSemantics { .. })
        ));

        let mut unknown_audience = encode_broker_authorization_plan(&plan());
        unknown_audience[2] = 4;
        assert!(matches!(
            decode_broker_authorization_plan(&unknown_audience, DecodeLimits::default()),
            Err(CanonicalCborError::UnknownRegistryValue {
                registry: "broker audience",
                ..
            })
        ));

        let mut unknown_protocol = encode_broker_authorization_plan(&plan());
        unknown_protocol[3] = 4;
        assert!(matches!(
            decode_broker_authorization_plan(&unknown_protocol, DecodeLimits::default()),
            Err(CanonicalCborError::UnknownRegistryValue {
                registry: "broker protocol",
                ..
            })
        ));
    }

    #[test]
    fn unknown_version_and_trailing_field_fail_closed() {
        let mut unknown_version = encode_broker_authorization_plan(&plan());
        unknown_version[1] = 2;
        assert!(matches!(
            decode_broker_authorization_plan(&unknown_version, DecodeLimits::default()),
            Err(CanonicalCborError::UnknownRegistryValue { .. })
        ));

        let original = plan();
        assert!(
            BrokerAuthorizationPlan::new(
                original.audience(),
                original.protocol(),
                ProtocolVersion::new(1, 1),
                original.assignment(),
                original.node(),
                original.ownership_authority().clone(),
                original.grants().to_vec(),
                original.policy_commitment(),
                original.revocation_scope(),
                original.issued_seconds(),
                original.expires_seconds(),
                original.required_features().to_vec(),
            )
            .is_ok()
        );
        assert!(matches!(
            BrokerAuthorizationPlan::new(
                original.audience(),
                original.protocol(),
                ProtocolVersion::new(1, 4),
                original.assignment(),
                original.node(),
                original.ownership_authority().clone(),
                original.grants().to_vec(),
                original.policy_commitment(),
                original.revocation_scope(),
                original.issued_seconds(),
                original.expires_seconds(),
                original.required_features().to_vec(),
            ),
            Err(InvalidBrokerAuthorizationPlan::ProtocolAudienceMismatch)
        ));

        let mut wrong_shape = encode_broker_authorization_plan(&plan());
        wrong_shape[0] = 0x8f;
        wrong_shape.push(0);
        assert!(matches!(
            decode_broker_authorization_plan(&wrong_shape, DecodeLimits::default()),
            Err(CanonicalCborError::ArrayLength { .. })
        ));
    }

    #[test]
    fn decode_limits_apply_before_plan_allocations() {
        let bytes = encode_broker_authorization_plan(&plan());
        let limits = DecodeLimits {
            maximum_bytes: bytes.len() - 1,
            ..DecodeLimits::default()
        };
        assert_eq!(
            decode_broker_authorization_plan(&bytes, limits),
            Err(CanonicalCborError::ObjectTooLarge)
        );
    }

    #[test]
    fn local_collection_ceiling_precedes_element_decode() {
        let mut encoder = Encoder::new();
        encoder.array(1_025);
        for _ in 0..1_025 {
            encoder.unsigned(0);
        }
        let bytes = encoder.finish();
        let mut decoder = Decoder::new(&bytes, DecodeLimits::default())
            .unwrap_or_else(|error| panic!("test decoder failed: {error}"));
        let result: Result<Vec<()>, _> = decode_bounded_vec(&mut decoder, 1_024, |_decoder| {
            panic!("oversized collection must fail before element decode")
        });
        assert!(matches!(
            result,
            Err(CanonicalCborError::CollectionTooLarge { .. })
        ));
    }

    #[test]
    fn unknown_required_feature_fails_closed() {
        let original = plan();
        let plan = BrokerAuthorizationPlan::new(
            original.audience(),
            original.protocol(),
            original.protocol_version(),
            original.assignment(),
            original.node(),
            original.ownership_authority().clone(),
            original.grants().to_vec(),
            original.policy_commitment(),
            original.revocation_scope(),
            original.issued_seconds(),
            original.expires_seconds(),
            vec![
                FeatureRef::new("aos.sandbox.enforcement.broker-ledger", 2, 0)
                    .unwrap_or_else(|error| panic!("test feature failed: {error}")),
            ],
        )
        .unwrap_or_else(|error| panic!("test plan failed: {error}"));

        assert!(matches!(
            decode_broker_authorization_plan(
                &encode_broker_authorization_plan(&plan),
                DecodeLimits::default()
            ),
            Err(CanonicalCborError::InvalidSemantics { .. })
        ));
    }
}

//! Canonical codecs for portable snapshot manifests and dependency claims.

use crate::model::{
    AttachmentSnapshot, ExternalDependency, OpaqueVersion, QuiesceEvidence, Receipt,
    RetentionClaim, Snapshot, SnapshotConsistency, SourceAssignment, StorageCheckpoint,
};
use crate::registry::DescriptorRole;
use crate::{
    AssignmentEpoch, AttachmentSlotId, IncarnationId, IssuerId, NetworkEndpointId, ObjectDigest,
    ResourceId, RestoreScopeId, SandboxId, SecretId, ServiceId,
};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::policy::{decode_set, encode_set};
use super::tree::{
    decode_descriptor_for_role, decode_feature, decode_vec, encode_descriptor, encode_feature,
    encode_slice, exact_bytes, semantics,
};
use super::view::{decode_view_mutation, view_mutation_code};

/// Encodes one snapshot in its exact portable v1 CBOR form.
#[must_use]
pub fn encode_snapshot(snapshot: &Snapshot) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(14);
    encoder.unsigned(1);
    encode_descriptor(&mut encoder, snapshot.sandbox_spec());
    encode_descriptor(&mut encoder, snapshot.historical_policy());
    encode_slice(&mut encoder, snapshot.ancestry(), encode_sandbox_id);
    encode_slice(&mut encoder, snapshot.private_roots(), encode_descriptor);
    encode_slice(
        &mut encoder,
        snapshot.storage_checkpoints(),
        encode_storage_checkpoint,
    );
    encode_set(
        &mut encoder,
        snapshot.retention_claims(),
        encode_retention_claim,
    );
    encode_descriptor(&mut encoder, snapshot.environment());
    encode_slice(
        &mut encoder,
        snapshot.attachments(),
        encode_attachment_snapshot,
    );
    encode_set(
        &mut encoder,
        snapshot.external_dependencies(),
        encode_external_dependency,
    );
    encoder.unsigned(consistency_code(snapshot.consistency()));
    encode_quiesce_evidence(&mut encoder, snapshot.quiesce_evidence());
    encode_slice(
        &mut encoder,
        snapshot.required_restore_features(),
        encode_feature,
    );
    encode_source_assignment(&mut encoder, snapshot.source_assignment());
    encoder.finish()
}

/// Decodes and validates one exact portable v1 snapshot object.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for profile, schema, registry, ordering, or
/// snapshot cross-field semantic violations.
pub fn decode_snapshot(bytes: &[u8], limits: DecodeLimits) -> Result<Snapshot, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(14)?;
    decoder.exact("snapshot version", 1)?;
    let sandbox_spec = decode_descriptor_for_role(&mut decoder, DescriptorRole::SnapshotSpec)?;
    let historical_policy =
        decode_descriptor_for_role(&mut decoder, DescriptorRole::SnapshotPolicy)?;
    let ancestry = decode_vec(&mut decoder, decode_sandbox_id)?;
    let private_roots = decode_vec(&mut decoder, decode_private_root)?;
    let storage_checkpoints = decode_vec(&mut decoder, decode_storage_checkpoint)?;
    let retention_claims = decode_set(&mut decoder, decode_retention_claim)?;
    let environment =
        decode_descriptor_for_role(&mut decoder, DescriptorRole::SnapshotEnvironment)?;
    let attachments = decode_vec(&mut decoder, decode_attachment_snapshot)?;
    let external_dependencies = decode_set(&mut decoder, decode_external_dependency)?;
    let consistency = decode_consistency(&mut decoder)?;
    let quiesce_evidence = decode_quiesce_evidence(&mut decoder)?;
    let required_restore_features = decode_vec(&mut decoder, decode_feature)?;
    let source_assignment = decode_source_assignment(&mut decoder)?;
    decoder.finish()?;

    Snapshot::new(
        sandbox_spec,
        historical_policy,
        ancestry,
        private_roots,
        storage_checkpoints,
        retention_claims,
        environment,
        attachments,
        external_dependencies,
        consistency,
        quiesce_evidence,
        required_restore_features,
        source_assignment,
    )
    .map_err(|error| semantics("snapshot", error))
}

fn encode_receipt(encoder: &mut Encoder, receipt: Receipt) {
    encoder.array(2);
    encoder.unsigned(1);
    encode_digest(encoder, receipt.digest());
}

fn decode_receipt(decoder: &mut Decoder<'_>) -> Result<Receipt, CanonicalCborError> {
    decoder.array(2)?;
    decoder.exact("receipt algorithm", 1)?;
    Ok(Receipt::sha256(decode_digest(decoder)?))
}

fn encode_retention_claim(encoder: &mut Encoder, claim: &RetentionClaim) {
    match claim {
        RetentionClaim::Storage {
            resource,
            opaque_version,
            version_sha256,
            receipt,
        } => {
            encoder.array(5);
            encoder.unsigned(0);
            encoder.bytes(resource.as_bytes());
            encoder.bytes(opaque_version.as_bytes());
            encode_digest(encoder, *version_sha256);
            encode_receipt(encoder, *receipt);
        }
        RetentionClaim::Content { object, receipt } => {
            encoder.array(3);
            encoder.unsigned(1);
            encode_descriptor(encoder, object);
            encode_receipt(encoder, *receipt);
        }
        RetentionClaim::Nix {
            environment,
            receipt,
        } => {
            encoder.array(3);
            encoder.unsigned(2);
            encode_descriptor(encoder, environment);
            encode_receipt(encoder, *receipt);
        }
        RetentionClaim::Service {
            service,
            checkpoint_version,
            checkpoint_sha256,
            receipt,
            available_until,
        } => {
            encoder.array(6);
            encoder.unsigned(3);
            encoder.bytes(service.as_bytes());
            encoder.bytes(checkpoint_version.as_bytes());
            encode_digest(encoder, *checkpoint_sha256);
            encode_receipt(encoder, *receipt);
            encode_optional_i64(encoder, *available_until);
        }
        RetentionClaim::Secret {
            issuer,
            secret,
            opaque_version,
            restore_scope,
            receipt,
            expires_seconds,
        } => {
            encoder.array(7);
            encoder.unsigned(4);
            encoder.bytes(issuer.as_bytes());
            encoder.bytes(secret.as_bytes());
            encoder.bytes(opaque_version.as_bytes());
            encoder.bytes(restore_scope.as_bytes());
            encode_receipt(encoder, *receipt);
            encode_optional_i64(encoder, *expires_seconds);
        }
    }
}

fn decode_retention_claim(decoder: &mut Decoder<'_>) -> Result<RetentionClaim, CanonicalCborError> {
    let length = decoder.array_len()?;
    let offset = decoder.position();
    let kind = decoder.closed("retention kind", 4)?;
    match kind {
        0 => {
            exact_union_length(length, 5, "storage retention")?;
            Ok(RetentionClaim::Storage {
                resource: decode_resource_id(decoder)?,
                opaque_version: decode_opaque_version(decoder)?,
                version_sha256: decode_digest(decoder)?,
                receipt: decode_receipt(decoder)?,
            })
        }
        1 => {
            exact_union_length(length, 3, "content retention")?;
            Ok(RetentionClaim::Content {
                object: decode_descriptor_for_role(decoder, DescriptorRole::ContentRetention)?,
                receipt: decode_receipt(decoder)?,
            })
        }
        2 => {
            exact_union_length(length, 3, "Nix retention")?;
            Ok(RetentionClaim::Nix {
                environment: decode_descriptor_for_role(
                    decoder,
                    DescriptorRole::EnvironmentDependency,
                )?,
                receipt: decode_receipt(decoder)?,
            })
        }
        3 => {
            exact_union_length(length, 6, "service retention")?;
            Ok(RetentionClaim::Service {
                service: decode_service_id(decoder)?,
                checkpoint_version: decode_opaque_version(decoder)?,
                checkpoint_sha256: decode_digest(decoder)?,
                receipt: decode_receipt(decoder)?,
                available_until: decoder.nullable(Decoder::signed)?,
            })
        }
        4 => {
            exact_union_length(length, 7, "secret retention")?;
            Ok(RetentionClaim::Secret {
                issuer: decode_issuer_id(decoder)?,
                secret: decode_secret_id(decoder)?,
                opaque_version: decode_opaque_version(decoder)?,
                restore_scope: decode_restore_scope_id(decoder)?,
                receipt: decode_receipt(decoder)?,
                expires_seconds: decoder.nullable(Decoder::signed)?,
            })
        }
        _ => Err(CanonicalCborError::UnknownRegistryValue {
            registry: "retention kind",
            value: kind,
            offset,
        }),
    }
}

fn encode_storage_checkpoint(encoder: &mut Encoder, checkpoint: &StorageCheckpoint) {
    encoder.array(2);
    encode_feature(encoder, checkpoint.backend());
    encode_descriptor(encoder, checkpoint.portable_state());
}

fn decode_storage_checkpoint(
    decoder: &mut Decoder<'_>,
) -> Result<StorageCheckpoint, CanonicalCborError> {
    decoder.array(2)?;
    Ok(StorageCheckpoint::new(
        decode_feature(decoder)?,
        decode_descriptor_for_role(decoder, DescriptorRole::PortableStorageState)?,
    ))
}

fn encode_attachment_snapshot(encoder: &mut Encoder, attachment: &AttachmentSnapshot) {
    encoder.array(3);
    encode_descriptor(encoder, attachment.view());
    encoder.bytes(attachment.destination_slot().as_bytes());
    encoder.unsigned(view_mutation_code(attachment.mode()));
}

fn decode_attachment_snapshot(
    decoder: &mut Decoder<'_>,
) -> Result<AttachmentSnapshot, CanonicalCborError> {
    decoder.array(3)?;
    Ok(AttachmentSnapshot::new(
        decode_descriptor_for_role(decoder, DescriptorRole::SnapshotAttachment)?,
        decode_attachment_slot_id(decoder)?,
        decode_view_mutation(decoder)?,
    ))
}

fn encode_external_dependency(encoder: &mut Encoder, dependency: &ExternalDependency) {
    match dependency {
        ExternalDependency::ImmutableView { view, required } => {
            encoder.array(3);
            encoder.unsigned(0);
            encode_descriptor(encoder, view);
            encoder.boolean(*required);
        }
        ExternalDependency::Package {
            environment,
            required,
        } => {
            encoder.array(3);
            encoder.unsigned(1);
            encode_descriptor(encoder, environment);
            encoder.boolean(*required);
        }
        ExternalDependency::Secret {
            issuer,
            secret,
            opaque_version,
            restore_scope,
            expires_seconds,
            required,
        } => {
            encoder.array(7);
            encoder.unsigned(2);
            encoder.bytes(issuer.as_bytes());
            encoder.bytes(secret.as_bytes());
            encoder.bytes(opaque_version.as_bytes());
            encoder.bytes(restore_scope.as_bytes());
            encode_optional_i64(encoder, *expires_seconds);
            encoder.boolean(*required);
        }
        ExternalDependency::Service {
            service,
            checkpoint_version,
            checkpoint_sha256,
            available_until,
            required,
        } => {
            encoder.array(6);
            encoder.unsigned(3);
            encoder.bytes(service.as_bytes());
            encoder.bytes(checkpoint_version.as_bytes());
            encode_digest(encoder, *checkpoint_sha256);
            encode_optional_i64(encoder, *available_until);
            encoder.boolean(*required);
        }
        ExternalDependency::Network {
            endpoint,
            contract_version,
            available_until,
            required,
        } => {
            encoder.array(5);
            encoder.unsigned(4);
            encoder.bytes(endpoint.as_bytes());
            encoder.bytes(contract_version.as_bytes());
            encode_optional_i64(encoder, *available_until);
            encoder.boolean(*required);
        }
    }
}

fn decode_external_dependency(
    decoder: &mut Decoder<'_>,
) -> Result<ExternalDependency, CanonicalCborError> {
    let length = decoder.array_len()?;
    let offset = decoder.position();
    let kind = decoder.closed("external dependency kind", 4)?;
    match kind {
        0 => {
            exact_union_length(length, 3, "immutable view dependency")?;
            Ok(ExternalDependency::ImmutableView {
                view: decode_descriptor_for_role(decoder, DescriptorRole::ImmutableViewDependency)?,
                required: decoder.boolean()?,
            })
        }
        1 => {
            exact_union_length(length, 3, "package dependency")?;
            Ok(ExternalDependency::Package {
                environment: decode_descriptor_for_role(
                    decoder,
                    DescriptorRole::EnvironmentDependency,
                )?,
                required: decoder.boolean()?,
            })
        }
        2 => {
            exact_union_length(length, 7, "secret dependency")?;
            Ok(ExternalDependency::Secret {
                issuer: decode_issuer_id(decoder)?,
                secret: decode_secret_id(decoder)?,
                opaque_version: decode_opaque_version(decoder)?,
                restore_scope: decode_restore_scope_id(decoder)?,
                expires_seconds: decoder.nullable(Decoder::signed)?,
                required: decoder.boolean()?,
            })
        }
        3 => {
            exact_union_length(length, 6, "service dependency")?;
            Ok(ExternalDependency::Service {
                service: decode_service_id(decoder)?,
                checkpoint_version: decode_opaque_version(decoder)?,
                checkpoint_sha256: decode_digest(decoder)?,
                available_until: decoder.nullable(Decoder::signed)?,
                required: decoder.boolean()?,
            })
        }
        4 => {
            exact_union_length(length, 5, "network dependency")?;
            Ok(ExternalDependency::Network {
                endpoint: decode_network_endpoint_id(decoder)?,
                contract_version: decode_opaque_version(decoder)?,
                available_until: decoder.nullable(Decoder::signed)?,
                required: decoder.boolean()?,
            })
        }
        _ => Err(CanonicalCborError::UnknownRegistryValue {
            registry: "external dependency kind",
            value: kind,
            offset,
        }),
    }
}

fn encode_quiesce_evidence(encoder: &mut Encoder, evidence: &QuiesceEvidence) {
    match evidence {
        QuiesceEvidence::None => {
            encoder.array(1);
            encoder.unsigned(0);
        }
        QuiesceEvidence::Guest {
            agent_version,
            result_sha256,
        } => {
            encoder.array(3);
            encoder.unsigned(1);
            encode_feature(encoder, agent_version);
            encode_digest(encoder, *result_sha256);
        }
        QuiesceEvidence::Backend {
            backend,
            result_sha256,
        } => {
            encoder.array(3);
            encoder.unsigned(2);
            encode_feature(encoder, backend);
            encode_digest(encoder, *result_sha256);
        }
    }
}

fn decode_quiesce_evidence(
    decoder: &mut Decoder<'_>,
) -> Result<QuiesceEvidence, CanonicalCborError> {
    let length = decoder.array_len()?;
    let kind = decoder.closed("quiesce evidence kind", 2)?;
    match kind {
        0 => {
            exact_union_length(length, 1, "no quiesce evidence")?;
            Ok(QuiesceEvidence::None)
        }
        1 => {
            exact_union_length(length, 3, "guest quiesce evidence")?;
            Ok(QuiesceEvidence::Guest {
                agent_version: decode_feature(decoder)?,
                result_sha256: decode_digest(decoder)?,
            })
        }
        2 => {
            exact_union_length(length, 3, "backend quiesce evidence")?;
            Ok(QuiesceEvidence::Backend {
                backend: decode_feature(decoder)?,
                result_sha256: decode_digest(decoder)?,
            })
        }
        _ => unreachable!("closed registry returned an unregistered value"),
    }
}

fn encode_source_assignment(encoder: &mut Encoder, source: SourceAssignment) {
    encoder.array(3);
    encoder.bytes(source.sandbox().as_bytes());
    encoder.bytes(source.incarnation().as_bytes());
    encoder.unsigned(source.epoch().get());
}

fn decode_source_assignment(
    decoder: &mut Decoder<'_>,
) -> Result<SourceAssignment, CanonicalCborError> {
    decoder.array(3)?;
    Ok(SourceAssignment::new(
        decode_sandbox_id(decoder)?,
        decode_incarnation_id(decoder)?,
        AssignmentEpoch::new(decoder.unsigned()?),
    ))
}

fn consistency_code(consistency: SnapshotConsistency) -> u64 {
    match consistency {
        SnapshotConsistency::CrashConsistent => 0,
        SnapshotConsistency::ApplicationQuiesced => 1,
        SnapshotConsistency::BackendExact => 2,
    }
}

fn decode_consistency(
    decoder: &mut Decoder<'_>,
) -> Result<SnapshotConsistency, CanonicalCborError> {
    Ok(match decoder.closed("snapshot consistency", 2)? {
        0 => SnapshotConsistency::CrashConsistent,
        1 => SnapshotConsistency::ApplicationQuiesced,
        2 => SnapshotConsistency::BackendExact,
        _ => unreachable!("closed registry returned an unregistered value"),
    })
}

fn encode_optional_i64(encoder: &mut Encoder, value: Option<i64>) {
    match value {
        Some(value) => encoder.signed(value),
        None => encoder.null(),
    }
}

fn encode_digest(encoder: &mut Encoder, digest: ObjectDigest) {
    encoder.bytes(digest.as_bytes());
}

fn decode_digest(decoder: &mut Decoder<'_>) -> Result<ObjectDigest, CanonicalCborError> {
    Ok(ObjectDigest::from_bytes(exact_bytes::<32>(decoder, 32)?))
}

fn decode_opaque_version(decoder: &mut Decoder<'_>) -> Result<OpaqueVersion, CanonicalCborError> {
    OpaqueVersion::new(decoder.bytes(255)?.to_vec())
        .map_err(|error| semantics("opaque version", error))
}

fn decode_private_root(
    decoder: &mut Decoder<'_>,
) -> Result<crate::ObjectDescriptor, CanonicalCborError> {
    decode_descriptor_for_role(decoder, DescriptorRole::SnapshotPrivateRoot)
}

fn exact_union_length(
    actual: usize,
    expected: usize,
    object: &'static str,
) -> Result<(), CanonicalCborError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CanonicalCborError::InvalidSemantics {
            object,
            message: format!("expected {expected} array members, found {actual}"),
        })
    }
}

macro_rules! decode_id {
    ($function:ident, $type:ty) => {
        fn $function(decoder: &mut Decoder<'_>) -> Result<$type, CanonicalCborError> {
            Ok(<$type>::from_bytes(exact_bytes::<16>(decoder, 16)?))
        }
    };
}

fn encode_sandbox_id(encoder: &mut Encoder, id: &SandboxId) {
    encoder.bytes(id.as_bytes());
}

decode_id!(decode_sandbox_id, SandboxId);
decode_id!(decode_incarnation_id, IncarnationId);
decode_id!(decode_attachment_slot_id, AttachmentSlotId);
decode_id!(decode_resource_id, ResourceId);
decode_id!(decode_service_id, ServiceId);
decode_id!(decode_issuer_id, IssuerId);
decode_id!(decode_secret_id, SecretId);
decode_id!(decode_restore_scope_id, RestoreScopeId);
decode_id!(decode_network_endpoint_id, NetworkEndpointId);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MediaType, ObjectDescriptor};

    fn descriptor(kind: &str, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(format!("application/vnd.aos.sandbox.{kind}.v1+cbor"))
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([byte; 32]),
            1,
        )
    }

    fn snapshot() -> Snapshot {
        Snapshot::new(
            descriptor("spec", 1),
            descriptor("policy", 2),
            vec![SandboxId::from_bytes([1; 16])],
            vec![descriptor("tree", 3)],
            Vec::new(),
            Vec::new(),
            descriptor("environment", 4),
            Vec::new(),
            Vec::new(),
            SnapshotConsistency::CrashConsistent,
            QuiesceEvidence::None,
            Vec::new(),
            SourceAssignment::new(
                SandboxId::from_bytes([9; 16]),
                IncarnationId::from_bytes([8; 16]),
                AssignmentEpoch::new(7),
            ),
        )
        .unwrap_or_else(|error| panic!("test snapshot failed: {error}"))
    }

    #[test]
    fn snapshot_round_trip_preserves_manifest() {
        let snapshot = snapshot();
        let encoded = encode_snapshot(&snapshot);

        assert_eq!(
            decode_snapshot(&encoded, DecodeLimits::default()),
            Ok(snapshot)
        );
    }

    #[test]
    fn unknown_dependency_kind_fails_closed() {
        let mut value = snapshot();
        value = Snapshot::new(
            value.sandbox_spec().clone(),
            value.historical_policy().clone(),
            value.ancestry().to_vec(),
            value.private_roots().to_vec(),
            value.storage_checkpoints().to_vec(),
            value.retention_claims().to_vec(),
            value.environment().clone(),
            value.attachments().to_vec(),
            vec![ExternalDependency::ImmutableView {
                view: descriptor("view", 5),
                required: true,
            }],
            value.consistency(),
            value.quiesce_evidence().clone(),
            value.required_restore_features().to_vec(),
            value.source_assignment(),
        )
        .unwrap_or_else(|error| panic!("test snapshot failed: {error}"));
        let mut encoded = encode_snapshot(&value);
        let position = encoded
            .windows(4)
            .position(|window| window == [0x81, 0x83, 0x00, 0x84])
            .unwrap_or_else(|| panic!("dependency encoding not found"));
        encoded[position + 2] = 5;

        assert!(matches!(
            decode_snapshot(&encoded, DecodeLimits::default()),
            Err(CanonicalCborError::UnknownRegistryValue {
                registry: "external dependency kind",
                value: 5,
                ..
            })
        ));
    }
}

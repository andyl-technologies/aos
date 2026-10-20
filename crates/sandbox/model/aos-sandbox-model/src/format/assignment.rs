//! Canonical codec for controller-known assignment manifests.

use crate::model::{
    AssignmentManifestV1, MAX_ANCESTRY_DEPTH, MAX_ASSIGNMENT_REQUIRED_FEATURES,
    MAX_ASSIGNMENT_SOURCE_COMMITMENTS, SandboxAncestry,
};
use crate::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, NodeId, ObjectDigest,
    ProjectId, ResourceDimension, ResourceVector, SandboxId,
};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{
    encode_descriptor, encode_feature, encode_slice,
    exact_bytes,
};

/// Encodes one assignment manifest in its exact canonical v1 form.
#[must_use]
pub fn encode_assignment_manifest_v1(manifest: &AssignmentManifestV1) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(17);
    encoder.unsigned(1);
    encoder.bytes(manifest.sandbox().as_bytes());
    encoder.bytes(manifest.project().as_bytes());
    encode_ids(&mut encoder, manifest.ancestry().ancestors());
    encoder.bytes(manifest.incarnation().as_bytes());
    encoder.bytes(manifest.node().as_bytes());
    encoder.unsigned(manifest.epoch().get());
    encoder.unsigned(manifest.desired_generation().get());
    encoder.unsigned(manifest.namespace_generation().get());
    encode_descriptor(&mut encoder, manifest.sandbox_spec());
    encode_descriptor(&mut encoder, manifest.policy());
    encode_descriptor(&mut encoder, manifest.environment());
    encode_descriptor(&mut encoder, manifest.root_view());
    encode_slice(
        &mut encoder,
        manifest.source_commitments(),
        encode_descriptor,
    );
    encoder.bytes(manifest.resource_commitment().as_bytes());
    encoder.array(ResourceDimension::COUNT);
    for dimension in ResourceDimension::ALL {
        encoder.unsigned(manifest.reservations().get(dimension));
    }
    encode_slice(&mut encoder, manifest.required_features(), encode_feature);
    encoder.finish()
}

/// Decodes one exact canonical v1 assignment manifest.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for noncanonical CBOR, wrong schema,
/// sentinel fields, invalid descriptors, or noncanonical bounded sets.
pub fn decode_assignment_manifest_v1(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<AssignmentManifestV1, CanonicalCborError> {
    decode_assignment_manifest_engine_v1(bytes, limits)
        .map_err(super::decode_attempt::DecodeFailure::into_canonical)
}

pub(crate) fn decode_assignment_manifest_engine_v1(
    bytes: &[u8],
    limits: DecodeLimits,
) -> super::decode_attempt::DecodeResult<AssignmentManifestV1> {
    use super::decode_attempt::typed_semantics;
    use super::tree::{decode_descriptor_engine, decode_feature_engine};

    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(17)?;
    decoder.exact("assignment manifest version", 1)?;
    let sandbox = SandboxId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let project = ProjectId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let ancestors = decoder.bounded_vec(MAX_ANCESTRY_DEPTH, |decoder| {
        exact_bytes(decoder, 16).map(SandboxId::from_bytes)
    })?;
    let ancestry = SandboxAncestry::new(sandbox, ancestors)
        .map_err(|cause| typed_semantics("assignment ancestry", cause))?;
    let incarnation = IncarnationId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let node = NodeId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let epoch = AssignmentEpoch::new(decoder.unsigned()?);
    let desired_generation = DesiredGeneration::new(decoder.unsigned()?);
    let namespace_generation = NamespaceGeneration::new(decoder.unsigned()?);
    let sandbox_spec = decode_descriptor_engine(&mut decoder)?;
    let policy = decode_descriptor_engine(&mut decoder)?;
    let environment = decode_descriptor_engine(&mut decoder)?;
    let root_view = decode_descriptor_engine(&mut decoder)?;
    let source_commitments =
        decoder.bounded_vec(MAX_ASSIGNMENT_SOURCE_COMMITMENTS, decode_descriptor_engine)?;
    let resource_commitment = ObjectDigest::from_bytes(exact_bytes(&mut decoder, 32)?);
    decoder.array(ResourceDimension::COUNT)?;
    let mut reservations = [0_u64; ResourceDimension::COUNT];
    for amount in &mut reservations {
        *amount = decoder.unsigned()?;
    }
    let required_features =
        decoder.bounded_vec(MAX_ASSIGNMENT_REQUIRED_FEATURES, decode_feature_engine)?;
    decoder.finish()?;

    AssignmentManifestV1::new(
        sandbox,
        project,
        ancestry,
        incarnation,
        node,
        epoch,
        desired_generation,
        namespace_generation,
        sandbox_spec,
        policy,
        environment,
        root_view,
        source_commitments,
        resource_commitment,
        ResourceVector::new(reservations),
        required_features,
    )
    .map_err(|cause| typed_semantics("assignment manifest", cause))
}

fn encode_ids(encoder: &mut Encoder, identities: &[SandboxId]) {
    encoder.array(identities.len());
    for identity in identities {
        encoder.bytes(identity.as_bytes());
    }
}


#[cfg(test)]
mod tests {
    use crate::{FeatureRef, MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType};

    use super::*;

    #[derive(Clone, Copy)]
    enum OversizedCollection {
        Ancestry,
        Sources,
        Features,
    }

    fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str().to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([byte; 32]),
            1,
        )
    }

    fn oversized_bytes(selected: OversizedCollection) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.array(17);
        encoder.unsigned(1);
        encoder.bytes(&[1; 16]);
        encoder.bytes(&[2; 16]);

        let ancestry_length = if matches!(selected, OversizedCollection::Ancestry) {
            MAX_ANCESTRY_DEPTH + 1
        } else {
            0
        };
        encoder.array(ancestry_length);
        for _ in 0..ancestry_length {
            encoder.bytes(&[3; 16]);
        }

        encoder.bytes(&[4; 16]);
        encoder.bytes(&[5; 16]);
        encoder.unsigned(1);
        encoder.unsigned(1);
        encoder.unsigned(1);
        encode_descriptor(&mut encoder, &descriptor(PortableMediaType::SandboxSpec, 6));
        encode_descriptor(&mut encoder, &descriptor(PortableMediaType::Policy, 7));
        encode_descriptor(&mut encoder, &descriptor(PortableMediaType::Environment, 8));
        encode_descriptor(&mut encoder, &descriptor(PortableMediaType::View, 9));

        let source_length = if matches!(selected, OversizedCollection::Sources) {
            MAX_ASSIGNMENT_SOURCE_COMMITMENTS + 1
        } else {
            0
        };
        encoder.array(source_length);
        for _ in 0..source_length {
            encode_descriptor(&mut encoder, &descriptor(PortableMediaType::Content, 10));
        }

        encoder.bytes(&[11; 32]);
        encoder.array(ResourceDimension::COUNT);
        for _ in 0..ResourceDimension::COUNT {
            encoder.unsigned(0);
        }

        let feature_length = if matches!(selected, OversizedCollection::Features) {
            MAX_ASSIGNMENT_REQUIRED_FEATURES + 1
        } else {
            0
        };
        encoder.array(feature_length);
        let feature = FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0)
            .unwrap_or_else(|error| panic!("test feature failed: {error}"));
        for _ in 0..feature_length {
            encode_feature(&mut encoder, &feature);
        }
        encoder.finish()
    }

    #[test]
    fn assignment_collection_ceilings_precede_allocation() {
        for selected in [
            OversizedCollection::Ancestry,
            OversizedCollection::Sources,
            OversizedCollection::Features,
        ] {
            assert!(matches!(
                decode_assignment_manifest_v1(&oversized_bytes(selected), DecodeLimits::default()),
                Err(CanonicalCborError::CollectionTooLarge { .. })
            ));
        }
    }
}

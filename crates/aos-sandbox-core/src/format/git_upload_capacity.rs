//! Canonical Git capacity DATA using the sole deterministic-CBOR engine.
//!
//! ```text
//! [1, project, resource, export, generation, generation_digest, audience_digest,
//!  ceilings[22], uniform[22], cpu_period, project_io, uniform_io, max_duration,
//!  [[broker-ledger,1,0],[cgroup-v2,1,0]]]
//! ```

use crate::{ExportId, ObjectDigest, ProjectId, ResourceDimension, ResourceId, ResourceVector};
use crate::model::git_upload_capacity::{
    GitUploadCapacityV1, MAXIMUM_GIT_UPLOAD_CAPACITY_BYTES_V1,
};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{decode_feature, encode_feature, exact_bytes, semantics};

/// Encodes the fixed canonical fourteen-field declaration.
#[must_use]
pub fn encode_git_upload_capacity_v1(value: &GitUploadCapacityV1) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(14);
    encoder.unsigned(1);
    encoder.bytes(value.project().as_bytes());
    encoder.bytes(value.resource().as_bytes());
    encoder.bytes(value.export().as_bytes());
    encoder.unsigned(value.generation());
    encoder.bytes(value.generation_commitment().as_bytes());
    encoder.bytes(value.audience_commitment().as_bytes());
    encode_vector(&mut encoder, value.ceilings());
    encode_vector(&mut encoder, value.uniform_reservation());
    encoder.unsigned(value.cpu_period_micros());
    encoder.unsigned(value.project_io_bytes_per_second());
    encoder.unsigned(value.uniform_io_bytes_per_second());
    encoder.unsigned(value.maximum_duration_nanoseconds());
    encoder.array(2);
    for feature in value.enforcement() {
        encode_feature(&mut encoder, feature);
    }
    encoder.finish()
}

/// Decodes the entire bounded canonical declaration before returning DATA.
///
/// # Errors
///
/// Rejects unknown versions, trailing/noncanonical bytes, bounds, identity,
/// enforcement or checked worst-case full-pool arithmetic violations.
pub fn decode_git_upload_capacity_v1(bytes: &[u8]) -> Result<GitUploadCapacityV1, CanonicalCborError> {
    let limits = DecodeLimits {
        maximum_bytes: MAXIMUM_GIT_UPLOAD_CAPACITY_BYTES_V1,
        maximum_collection_items: 22,
        maximum_total_items: 67,
        maximum_byte_string_bytes: 32,
        maximum_text_bytes: 37,
        maximum_depth: 4,
    };
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(14)?;
    decoder.exact("Git upload capacity version", 1)?;
    let project = ProjectId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let resource = ResourceId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let export = ExportId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let generation = decoder.unsigned()?;
    let generation_commitment = ObjectDigest::from_bytes(exact_bytes(&mut decoder, 32)?);
    let audience_commitment = ObjectDigest::from_bytes(exact_bytes(&mut decoder, 32)?);
    let ceilings = decode_vector(&mut decoder)?;
    let uniform_reservation = decode_vector(&mut decoder)?;
    let cpu_period_micros = decoder.unsigned()?;
    let project_io_bytes_per_second = decoder.unsigned()?;
    let uniform_io_bytes_per_second = decoder.unsigned()?;
    let maximum_duration_nanoseconds = decoder.unsigned()?;
    decoder.array(2)?;
    let enforcement = [decode_feature(&mut decoder)?, decode_feature(&mut decoder)?];
    decoder.finish()?;

    GitUploadCapacityV1::new(
        project,
        resource,
        export,
        generation,
        generation_commitment,
        audience_commitment,
        ceilings,
        uniform_reservation,
        cpu_period_micros,
        project_io_bytes_per_second,
        uniform_io_bytes_per_second,
        maximum_duration_nanoseconds,
        enforcement,
    )
    .map_err(|error| semantics("Git upload capacity", error))
}

fn encode_vector(encoder: &mut Encoder, value: ResourceVector) {
    encoder.array(ResourceDimension::COUNT);
    for dimension in ResourceDimension::ALL {
        encoder.unsigned(value.get(dimension));
    }
}

fn decode_vector(decoder: &mut Decoder<'_>) -> Result<ResourceVector, CanonicalCborError> {
    decoder.array(ResourceDimension::COUNT)?;
    let mut values = [0; ResourceDimension::COUNT];
    for value in &mut values {
        *value = decoder.unsigned()?;
    }
    Ok(ResourceVector::new(values))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FeatureRef;

    fn capacity() -> GitUploadCapacityV1 {
        let ceilings = ResourceVector::new([u64::MAX; ResourceDimension::COUNT])
            .with(ResourceDimension::ConcurrentOperations, 2);
        let uniform = ResourceVector::new([1; ResourceDimension::COUNT]);
        let enforcement = [
            FeatureRef::new("aos.sandbox.enforcement.broker-ledger", 1, 0).unwrap(),
            FeatureRef::new("aos.sandbox.enforcement.cgroup-v2", 1, 0).unwrap(),
        ];
        GitUploadCapacityV1::new(
            ProjectId::from_bytes([1; 16]),
            ResourceId::from_bytes([2; 16]),
            ExportId::from_bytes([3; 16]),
            1,
            ObjectDigest::from_bytes([4; 32]),
            ObjectDigest::from_bytes([5; 32]),
            ceilings,
            uniform,
            100_000,
            2,
            1,
            1_000_000_000,
            enforcement,
        ).unwrap()
    }

    #[test]
    fn canonical_capacity_round_trips_within_fixed_bounds() {
        let value = capacity();
        let bytes = encode_git_upload_capacity_v1(&value);

        assert!(bytes.len() <= MAXIMUM_GIT_UPLOAD_CAPACITY_BYTES_V1);
        assert_eq!(decode_git_upload_capacity_v1(&bytes).unwrap(), value);
    }

    #[test]
    fn trailing_bytes_and_unknown_version_are_not_capacity_data() {
        let mut bytes = encode_git_upload_capacity_v1(&capacity());
        bytes.push(0);
        assert!(decode_git_upload_capacity_v1(&bytes).is_err());

        bytes.pop();
        bytes[1] = 2;
        assert!(decode_git_upload_capacity_v1(&bytes).is_err());
    }

    #[test]
    fn full_pool_overflow_is_rejected_by_existing_account_arithmetic() {
        let value = capacity();
        // Pure DATA only: reconstruct with one slice too large for two slots.
        let uniform = value.uniform_reservation()
            .with(ResourceDimension::MemoryBytes, u64::MAX);
        let result = GitUploadCapacityV1::new(
            value.project(), value.resource(), value.export(), value.generation(),
            value.generation_commitment(), value.audience_commitment(), value.ceilings(),
            uniform, value.cpu_period_micros(), value.project_io_bytes_per_second(),
            value.uniform_io_bytes_per_second(), value.maximum_duration_nanoseconds(),
            value.enforcement().clone(),
        );

        assert!(matches!(result, Err(crate::InvalidGitUploadCapacityV1::Accounting(_))));
    }
}

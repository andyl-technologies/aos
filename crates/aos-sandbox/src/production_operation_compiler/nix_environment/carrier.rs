//! Bounded original Start admission data retained inside one Controller effect.
//!
//! ```text
//! AOSNCA02 || version:u16be=2 || reserved:6=0 || json-length:u32be ||
//! canonical-json || sha256(domain || preceding-bytes):32
//! ```
//!
//! Decoding preserves originals only. It grants neither live startup, current
//! assignment, broker session/floor custody nor permission to realize a build.

use std::io::{self, Write};

use aos_sandbox_core::{ObjectDigest, OperationId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::NixStartAdmissionErrorV2;
use super::authority::CheckedStartAuthorityV2;

const MAGIC: &[u8; 8] = b"AOSNCA02";
const HEADER_BYTES: usize = 20;
const DIGEST_BYTES: usize = 32;
const DOMAIN: &[u8] = b"aos.sandbox.nix.original-start-carrier.v2\0";
pub(super) const MAXIMUM_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalAssignmentV2 {
    pub(super) binding: Vec<u8>,
    pub(super) binding_digest: ObjectDigest,
    pub(super) assignment: Vec<u8>,
    pub(super) publication: Vec<u8>,
    pub(super) publication_digest: ObjectDigest,
    pub(super) lease: Vec<u8>,
    pub(super) signature: Vec<u8>,
    pub(super) receipt: Vec<u8>,
    pub(super) receipt_signature: Vec<u8>,
}

/// Retains exact historical admission originals, without issuing live authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NixStartAdmissionCarrierV2 {
    pub(super) operation: OperationId,
    pub(super) request_digest: [u8; 32],
    pub(super) authority: CheckedStartAuthorityV2,
    pub(super) assignment: OriginalAssignmentV2,
    pub(super) recipe: Vec<u8>,
    pub(super) recipe_digest: ObjectDigest,
    pub(super) credential_commitments: Vec<[u8; 32]>,
    pub(super) ordinary_effect: Vec<u8>,
    pub(super) desired_key: Vec<u8>,
    pub(super) desired_value: Vec<u8>,
    pub(super) original_resource_version: Vec<u8>,
    pub(super) original_incarnation: Vec<u8>,
    pub(super) original_generation: u64,
}

impl NixStartAdmissionCarrierV2 {
    pub(crate) fn ordinary_effect(&self) -> &[u8] {
        &self.ordinary_effect
    }

    pub(crate) fn operation(&self) -> OperationId {
        self.operation
    }

    pub(crate) fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    pub(crate) fn desired(&self) -> (&[u8], &[u8]) {
        (&self.desired_key, &self.desired_value)
    }

    pub(crate) fn original_generation(&self) -> u64 {
        self.original_generation
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, NixStartAdmissionErrorV2> {
        self.validate()?;
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            limit: MAXIMUM_BYTES - HEADER_BYTES - DIGEST_BYTES,
        };
        serde_json::to_writer(&mut writer, self)?;
        let length = u32::try_from(writer.bytes.len()).map_err(|_| NixStartAdmissionErrorV2::Invalid)?;

        let mut bytes = Vec::with_capacity(HEADER_BYTES + writer.bytes.len() + DIGEST_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&writer.bytes);
        let digest = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&bytes)
            .finalize();
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>, NixStartAdmissionErrorV2> {
        if !bytes.starts_with(MAGIC) {
            return Ok(None);
        }
        if !(HEADER_BYTES + DIGEST_BYTES..=MAXIMUM_BYTES).contains(&bytes.len())
            || bytes[8..10] != 2_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        let length_bytes = bytes[16..20].try_into()
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        let end = HEADER_BYTES.checked_add(length)
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;
        if end.checked_add(DIGEST_BYTES) != Some(bytes.len())
            || Sha256::new().chain_update(DOMAIN).chain_update(&bytes[..end]).finalize().as_slice() != &bytes[end..]
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }

        let carrier: Self = serde_json::from_slice(&bytes[HEADER_BYTES..end])?;
        if carrier.encode()? != bytes {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        Ok(Some(carrier))
    }

    pub(super) fn validate(&self) -> Result<(), NixStartAdmissionErrorV2> {
        self.authority.validate()?;
        let context = crate::reconciler::PublicMutationEffectV1::decode_plain(&self.ordinary_effect)
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;
        if self.operation.as_bytes() == &[0; 16]
            || self.request_digest == [0; 32]
            || context.caller() != self.authority.holder
            || context.project() != self.authority.project
            || context.accepted_wall_seconds() != self.authority.accepted_wall_seconds
            || context.canonical_request() != self.authority.original_request
            || self.recipe.is_empty()
            || self.recipe.len() > aos_sandbox_protocol::nix_build::NIX_REQUEST_MAXIMUM_BYTES_V2
            || self.recipe_digest.as_bytes() == &[0; 32]
            || self.credential_commitments.len() != 12
            || self.credential_commitments.contains(&[0; 32])
            || self.desired_key.is_empty()
            || self.desired_value.is_empty()
            || self.original_resource_version.is_empty()
            || self.original_incarnation.len() != 16
            || self.original_incarnation == [0; 16]
            || self.original_generation == 0
            || self.assignment.binding_digest.as_bytes() == &[0; 32]
            || self.assignment.publication_digest.as_bytes() == &[0; 32]
            || [&self.assignment.binding, &self.assignment.assignment,
                &self.assignment.publication, &self.assignment.lease,
                &self.assignment.signature, &self.assignment.receipt,
                &self.assignment.receipt_signature].iter().any(|bytes| bytes.is_empty())
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        self.require_original_preconditions()?;
        Ok(())
    }

    fn require_original_preconditions(&self) -> Result<(), NixStartAdmissionErrorV2> {
        use crate::controller_service::public_projection::{
            PublicProjectionResourceV1, decode_checked_public_projection_v1,
        };

        let request = crate::public_mutation_compiler::ResolvedPublicMutationRequestV1::decode(
            &self.authority.original_request,
        ).map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        let crate::cli_model::DormantSandboxRequestKindV1::Start(request) = request.request() else {
            return Err(NixStartAdmissionErrorV2::Invalid);
        };
        let mutation = request.mutation.as_option().ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let projection = decode_checked_public_projection_v1(&self.desired_key, &self.desired_value)
            .map_err(|_| NixStartAdmissionErrorV2::Invalid)?;
        let PublicProjectionResourceV1::Sandbox(sandbox) = projection.resource() else {
            return Err(NixStartAdmissionErrorV2::Invalid);
        };
        let desired = sandbox.desired.as_option().ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let next_generation = self.original_generation.checked_add(1)
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let expected_version = super::super::public_mutation::resource_version(
            self.operation, crate::controller_query::PublicOperationMethodV1::StartSandbox,
            next_generation, self.request_digest,
        );
        if mutation.expected_resource_version != self.original_resource_version
            || (!mutation.expected_incarnation_id.is_empty()
                && mutation.expected_incarnation_id != self.original_incarnation)
            || projection.operation() != self.operation
            || projection.project() != self.authority.project
            || sandbox.sandbox_id != request.sandbox_id
            || sandbox.project_id != self.authority.project.as_bytes()
            || sandbox.resource_version != expected_version
            || desired.generation != next_generation
            || desired.lifecycle.as_known() != Some(aos_proto::aos::sandbox::v1::DesiredLifecycle::DESIRED_LIFECYCLE_RUNNING)
            || sandbox.updated_at.as_option().is_none_or(|time| {
                time.seconds != self.authority.accepted_wall_seconds || time.nanoseconds != 0
            })
        {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        Ok(())
    }
}

/// Counts the complete canonical JSON while refusing allocation above the cap.
struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().checked_add(bytes.len()).is_none_or(|length| length > self.limit) {
            return Err(io::Error::other("retained Nix Start carrier exceeds its fixed bound"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_json_writer_refuses_crossing_the_aggregate_bound() {
        let mut writer = BoundedWriter { bytes: Vec::new(), limit: 4 };
        writer.write_all(b"1234").unwrap();

        assert!(writer.write_all(b"5").is_err());
        assert_eq!(writer.bytes, b"1234");
    }

    #[test]
    fn recognized_carrier_rejects_reserved_bytes_truncation_and_oversize() {
        let mut bytes = vec![0; HEADER_BYTES + DIGEST_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
        bytes[10] = 1;

        assert!(NixStartAdmissionCarrierV2::decode(&bytes).is_err());
        assert!(NixStartAdmissionCarrierV2::decode(MAGIC).is_err());
        bytes.resize(MAXIMUM_BYTES + 1, 0);
        assert!(NixStartAdmissionCarrierV2::decode(&bytes).is_err());
        assert_eq!(NixStartAdmissionCarrierV2::decode(b"AOSPME01").unwrap(), None);
    }
}

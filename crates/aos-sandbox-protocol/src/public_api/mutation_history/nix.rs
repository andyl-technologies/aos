//! Complete canonical AOSNCA02 historical Start DATA, comparisons and bounded encoding.
//! Native admission, clocks, catalog selection and Journal/current loans remain upper.
//!
//! ```text
//! AOSNCA02 | version:u16be=2 | reserved:6 | json-length:u32be | JSON | SHA256:32
//! ```

use std::io::{self, Write};

use aos_sandbox_core::{
    CapabilityRecord, ObjectDescriptor, ObjectDigest, OperationId, PrincipalId, ProjectId,
};
use aos_sandbox_ownership_protocol::{
    SignedOwnershipLease, UnverifiedOwnershipLeaseResponse, OwnershipLeaseAcquisitionError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use super::NixHistoryDataError;
use crate::public_api::public_mutation_context::PublicMutationContextV1;

const MAGIC: &[u8; 8] = b"AOSNCA02";
const HEADER_BYTES: usize = 20;
const DIGEST_BYTES: usize = 32;
const DOMAIN: &[u8] = b"aos.sandbox.nix.original-start-carrier.v2\0";
/// Bounds the complete canonical historical Nix Start carrier and preimage aggregate.
pub const MAXIMUM_BYTES: usize = 1_048_576;

/// Historical checked coordinates, never a capability or resumed authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalPublicMutationCoordinatesV2 {
    /// Immutable capability resolved by the original protected authorization.
    capability: [u8; 16],
    /// Revocation scope actually checked for that capability.
    revocation_scope: [u8; 16],
    /// Accepted revocation head generation.
    revocation_generation: u64,
    /// Original effective project policy commitment.
    policy_digest: [u8; 32],
    /// Original protected policy head generation.
    policy_generation: u64,
    /// Original checked controller audience.
    controller: [u8; 16],
    /// Original controller audience head generation.
    controller_generation: u64,
    /// Inclusive original capability validity start.
    capability_not_before: i64,
    /// Exclusive original capability validity end.
    capability_expires_at: i64,
    /// Inclusive original policy validity start.
    policy_not_before: i64,
    /// Exclusive original policy validity end.
    policy_expires_at: i64,
    /// Stable registered certificate-derived holder binding, not the exporter.
    channel_binding: [u8; 32],
    /// Historical TLS exporter commitment; reconnect does not reuse its proof.
    session_commitment: [u8; 32],
    /// Original authorization revision, including its protected clock floor.
    authorization_revision: [u8; 32],
}

impl OriginalPublicMutationCoordinatesV2 {
    /// Retains ordered historical DATA without validating or authorizing it.
    ///
    /// Native producers assemble these values in their original evaluation order.
    #[must_use]
    pub fn from_historical_parts(
        parts: (
            [u8; 16],
            [u8; 16],
            u64,
            [u8; 32],
            u64,
            [u8; 16],
            u64,
            i64,
            i64,
            i64,
            i64,
            [u8; 32],
            [u8; 32],
            [u8; 32],
        ),
    ) -> Self {
        let (
            capability,
            revocation_scope,
            revocation_generation,
            policy_digest,
            policy_generation,
            controller,
            controller_generation,
            capability_not_before,
            capability_expires_at,
            policy_not_before,
            policy_expires_at,
            channel_binding,
            session_commitment,
            authorization_revision,
        ) = parts;
        Self {
            capability,
            revocation_scope,
            revocation_generation,
            policy_digest,
            policy_generation,
            controller,
            controller_generation,
            capability_not_before,
            capability_expires_at,
            policy_not_before,
            policy_expires_at,
            channel_binding,
            session_commitment,
            authorization_revision,
        }
    }

    /// Returns the retained historical capability DATA.
    #[must_use]
    pub const fn capability(&self) -> [u8; 16] {
        self.capability
    }

    /// Returns the retained historical policy generation DATA.
    #[must_use]
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    /// Returns the retained historical controller generation DATA.
    #[must_use]
    pub const fn controller_generation(&self) -> u64 {
        self.controller_generation
    }

    /// Returns the retained historical capability not before DATA.
    #[must_use]
    pub const fn capability_not_before(&self) -> i64 {
        self.capability_not_before
    }

    /// Returns the retained historical capability expires at DATA.
    #[must_use]
    pub const fn capability_expires_at(&self) -> i64 {
        self.capability_expires_at
    }

    /// Returns the retained historical policy not before DATA.
    #[must_use]
    pub const fn policy_not_before(&self) -> i64 {
        self.policy_not_before
    }

    /// Returns the retained historical policy expires at DATA.
    #[must_use]
    pub const fn policy_expires_at(&self) -> i64 {
        self.policy_expires_at
    }

    /// Returns the retained historical channel binding DATA.
    #[must_use]
    pub const fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }

    /// Returns the retained historical session commitment DATA.
    #[must_use]
    pub const fn session_commitment(&self) -> [u8; 32] {
        self.session_commitment
    }

    /// Compares the original scope independently of a reconnect session/revision.
    pub fn same_original_scope(&self, checked: &Self) -> bool {
        // Current authorize() has independently checked the authenticated channel.
        // Historical session/clock coordinates are retained, not compared as if a
        // reconnect had to revive the original session or reconstruct its proof.
        self.capability == checked.capability
            && self.revocation_scope == checked.revocation_scope
            && self.revocation_generation == checked.revocation_generation
            && self.policy_digest == checked.policy_digest
            && self.policy_generation == checked.policy_generation
            && self.controller == checked.controller
            && self.controller_generation == checked.controller_generation
            && self.capability_not_before == checked.capability_not_before
            && self.capability_expires_at == checked.capability_expires_at
            && self.policy_not_before == checked.policy_not_before
            && self.policy_expires_at == checked.policy_expires_at
            && self.channel_binding == checked.channel_binding
    }

    /// Requires exact coordinates after disregarding the observation revision.
    ///
    /// # Errors
    /// Refuses changes to any other retained authority coordinate.
    pub fn require_coordinate_identity(
        self,
        mut observed: Self,
    ) -> Result<(), NixHistoryDataError> {
        // The common evaluator advances the observation's protected time floor.
        // Every signed authority coordinate and historical session remains exact.
        observed.authorization_revision = self.authorization_revision;
        if observed != self {
            return Err(NixHistoryDataError::Invalid);
        }
        Ok(())
    }
}

/// Retains original checked Start claims as DATA without reviving their evaluator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckedStartAuthorityV2 {
    capability: CapabilityRecord,
    coordinates: OriginalPublicMutationCoordinatesV2,
    holder: PrincipalId,
    project: ProjectId,
    accepted_wall_seconds: i64,
    policy: ObjectDescriptor,
    canonical_policy: Vec<u8>,
    original_request: Vec<u8>,
    original_trust: [[u8; 32]; 4],
}

impl CheckedStartAuthorityV2 {
    /// Retains ordered historical DATA without validating or authorizing it.
    ///
    /// Native producers assemble these values in their original evaluation order.
    #[must_use]
    pub fn from_historical_parts(
        parts: (
            CapabilityRecord,
            OriginalPublicMutationCoordinatesV2,
            PrincipalId,
            ProjectId,
            i64,
            ObjectDescriptor,
            Vec<u8>,
            Vec<u8>,
            [[u8; 32]; 4],
        ),
    ) -> Self {
        let (
            capability,
            coordinates,
            holder,
            project,
            accepted_wall_seconds,
            policy,
            canonical_policy,
            original_request,
            original_trust,
        ) = parts;
        Self {
            capability,
            coordinates,
            holder,
            project,
            accepted_wall_seconds,
            policy,
            canonical_policy,
            original_request,
            original_trust,
        }
    }

    /// Returns the retained historical capability DATA.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityRecord {
        &self.capability
    }

    /// Returns the retained historical coordinates DATA.
    #[must_use]
    pub const fn coordinates(&self) -> OriginalPublicMutationCoordinatesV2 {
        self.coordinates
    }

    /// Returns the retained historical holder DATA.
    #[must_use]
    pub const fn holder(&self) -> PrincipalId {
        self.holder
    }

    /// Returns the retained historical project DATA.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the retained historical accepted wall seconds DATA.
    #[must_use]
    pub const fn accepted_wall_seconds(&self) -> i64 {
        self.accepted_wall_seconds
    }

    /// Returns the retained historical policy DATA.
    #[must_use]
    pub const fn policy(&self) -> &ObjectDescriptor {
        &self.policy
    }

    /// Borrows the original canonical policy.
    pub fn canonical_policy(&self) -> &[u8] {
        &self.canonical_policy
    }

    /// Borrows the exact original request envelope.
    pub fn original_request(&self) -> &[u8] {
        &self.original_request
    }

    /// Checks the complete historical scalar and canonical context joins.
    ///
    /// # Errors
    /// Refuses the original malformed claims or semantic disagreement in original order.
    pub fn validate(&self) -> Result<(), NixHistoryDataError> {
        let claims = self.capability.claims();
        let policy = aos_sandbox_policy::PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            self.project,
            self.coordinates.policy_generation,
            self.coordinates.policy_not_before,
            self.coordinates.policy_expires_at,
            &self.canonical_policy,
            aos_sandbox_core::DecodeLimits::default(),
        )
        .map_err(|_| NixHistoryDataError::Invalid)?;
        let request = crate::public_api::mutation::ResolvedPublicMutationRequestV1::decode(
            &self.original_request,
        )
        .map_err(|_| NixHistoryDataError::Invalid)?;
        if !matches!(
            request.request(),
            crate::public_api::request::DormantSandboxRequestKindV1::Start(_)
        ) || claims.holder != self.holder
            || claims.project != self.project
            || claims.id.as_bytes() != &self.coordinates.capability
            || claims.channel_binding.as_bytes() != &self.coordinates.channel_binding
            || claims.revocation_scope.as_bytes() != &self.coordinates.revocation_scope
            || claims.revocation_generation.get() != self.coordinates.revocation_generation
            || claims.policy_digest != self.policy.digest()
            || self.policy.digest().as_bytes() != &self.coordinates.policy_digest
            || policy.descriptor() != &self.policy
            || claims.not_before != self.coordinates.capability_not_before
            || claims.expires_at != self.coordinates.capability_expires_at
            || self.coordinates.controller_generation == 0
            || self.coordinates.controller == [0; 16]
            || self.coordinates.authorization_revision == [0; 32]
            || self.coordinates.session_commitment == [0; 32]
            || self.original_trust.contains(&[0; 32])
            || self.accepted_wall_seconds < claims.not_before
            || self.accepted_wall_seconds < policy.not_before()
            || self.accepted_wall_seconds >= claims.expires_at
            || self.accepted_wall_seconds >= policy.expires_at()
        {
            return Err(NixHistoryDataError::Invalid);
        }
        Ok(())
    }

    /// Compares independently supplied historical decision DATA after both validations.
    ///
    /// # Errors
    /// Refuses original claim, policy, trust or acceptance-bound disagreement.
    pub fn require_current_decision(&self, current: &Self) -> Result<(), NixHistoryDataError> {
        self.validate()?;
        current.validate()?;
        // A reconnect may change the historical exporter and protected clock
        // revision. It cannot change the original capability, policy or bounds.
        if self.capability != current.capability
            || self.policy != current.policy
            || self.canonical_policy != current.canonical_policy
            || self.holder != current.holder
            || self.project != current.project
            || self.original_request != current.original_request
            || self.original_trust != current.original_trust
            || self.coordinates.controller != current.coordinates.controller
            || self.coordinates.controller_generation != current.coordinates.controller_generation
            || self.coordinates.policy_generation != current.coordinates.policy_generation
            || self.coordinates.policy_not_before != current.coordinates.policy_not_before
            || self.coordinates.policy_expires_at != current.coordinates.policy_expires_at
            || current.accepted_wall_seconds < self.accepted_wall_seconds
            || current.accepted_wall_seconds >= self.coordinates.capability_expires_at
            || current.accepted_wall_seconds >= self.coordinates.policy_expires_at
        {
            return Err(NixHistoryDataError::Invalid);
        }
        Ok(())
    }
}

/// Owns all seven historical assignment byte families and their original digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalAssignmentV2 {
    binding: Vec<u8>,
    binding_digest: ObjectDigest,
    assignment: Vec<u8>,
    publication: Vec<u8>,
    publication_digest: ObjectDigest,
    lease: Vec<u8>,
    signature: Vec<u8>,
    receipt: Vec<u8>,
    receipt_signature: Vec<u8>,
}

impl OriginalAssignmentV2 {
    /// Requires all four exact canonical byte families from the borrowed lease.
    ///
    /// # Errors
    /// Refuses any historical lease, signature, receipt or receipt-signature mismatch.
    pub fn require_original_lease(
        &self,
        lease: &SignedOwnershipLease,
    ) -> Result<(), NixHistoryDataError> {
        if lease.canonical_lease() != self.lease
            || lease.canonical_signature() != self.signature
            || lease.canonical_receipt() != self.receipt
            || lease.canonical_receipt_signature() != self.receipt_signature
        {
            return Err(NixHistoryDataError::Invalid);
        }
        Ok(())
    }

    /// Clones the original transport bytes without verifying or granting a lease.
    ///
    /// # Errors
    /// Propagates the established ownership transport field bounds.
    pub fn clone_unverified_response(
        &self,
    ) -> Result<UnverifiedOwnershipLeaseResponse, OwnershipLeaseAcquisitionError> {
        UnverifiedOwnershipLeaseResponse::from_transport(
            self.lease.clone(),
            self.signature.clone(),
            self.receipt.clone(),
            self.receipt_signature.clone(),
        )
    }
}

/// Projects every original preimage and both digests without copying its bytes.
pub struct AssignmentPreimagesV2<'original> {
    bytes: [&'original [u8]; 7],
    binding_digest: ObjectDigest,
    publication_digest: ObjectDigest,
}

impl<'original> AssignmentPreimagesV2<'original> {
    /// Borrows the seven ordered original byte families and their two digests.
    pub const fn from_historical_parts(
        bytes: [&'original [u8]; 7],
        binding_digest: ObjectDigest,
        publication_digest: ObjectDigest,
    ) -> Self {
        Self {
            bytes,
            binding_digest,
            publication_digest,
        }
    }

    /// Applies the complete checked aggregate bound without allocating.
    ///
    /// # Errors
    /// Refuses overflow or a total exceeding the retained carrier bound.
    pub fn require_lengths(&self) -> Result<(), NixHistoryDataError> {
        require_assignment_preimage_lengths(self.bytes.map(|original| original.len()))
    }

    /// Copies all original byte families in their established field order.
    pub fn into_owned(self) -> OriginalAssignmentV2 {
        let [
            binding,
            assignment,
            publication,
            lease,
            signature,
            receipt,
            receipt_signature,
        ] = self.bytes;

        OriginalAssignmentV2 {
            binding: binding.to_vec(),
            binding_digest: self.binding_digest,
            assignment: assignment.to_vec(),
            publication: publication.to_vec(),
            publication_digest: self.publication_digest,
            lease: lease.to_vec(),
            signature: signature.to_vec(),
            receipt: receipt.to_vec(),
            receipt_signature: receipt_signature.to_vec(),
        }
    }

    /// Compares all seven preimages before both historical digests.
    pub fn matches_original(&self, original: &OriginalAssignmentV2) -> bool {
        self.bytes
            == [
                original.binding.as_slice(),
                original.assignment.as_slice(),
                original.publication.as_slice(),
                original.lease.as_slice(),
                original.signature.as_slice(),
                original.receipt.as_slice(),
                original.receipt_signature.as_slice(),
            ]
            && self.binding_digest == original.binding_digest
            && self.publication_digest == original.publication_digest
    }
}

fn require_assignment_preimage_lengths(lengths: [usize; 7]) -> Result<(), NixHistoryDataError> {
    lengths.into_iter().try_fold(0_usize, |total, length| {
        total
            .checked_add(length)
            .filter(|length| *length <= MAXIMUM_BYTES)
            .ok_or(NixHistoryDataError::Invalid)
    })?;
    Ok(())
}

/// Retains exact historical admission originals, without issuing live authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NixStartAdmissionCarrierV2 {
    operation: OperationId,
    request_digest: [u8; 32],
    authority: CheckedStartAuthorityV2,
    assignment: OriginalAssignmentV2,
    recipe: Vec<u8>,
    recipe_digest: ObjectDigest,
    credential_commitments: Vec<[u8; 32]>,
    ordinary_effect: Vec<u8>,
    desired_key: Vec<u8>,
    desired_value: Vec<u8>,
    original_resource_version: Vec<u8>,
    original_incarnation: Vec<u8>,
    original_generation: u64,
}

impl NixStartAdmissionCarrierV2 {
    /// Retains ordered historical DATA without validating or authorizing it.
    ///
    /// Native producers assemble these values in their original evaluation order.
    #[must_use]
    pub fn from_historical_parts(
        parts: (
            OperationId,
            [u8; 32],
            CheckedStartAuthorityV2,
            OriginalAssignmentV2,
            Vec<u8>,
            ObjectDigest,
            Vec<[u8; 32]>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            u64,
        ),
    ) -> Self {
        let (
            operation,
            request_digest,
            authority,
            assignment,
            recipe,
            recipe_digest,
            credential_commitments,
            ordinary_effect,
            desired_key,
            desired_value,
            original_resource_version,
            original_incarnation,
            original_generation,
        ) = parts;
        Self {
            operation,
            request_digest,
            authority,
            assignment,
            recipe,
            recipe_digest,
            credential_commitments,
            ordinary_effect,
            desired_key,
            desired_value,
            original_resource_version,
            original_incarnation,
            original_generation,
        }
    }

    /// Returns the retained historical authority DATA.
    #[must_use]
    pub const fn authority(&self) -> &CheckedStartAuthorityV2 {
        &self.authority
    }

    /// Returns the retained historical assignment DATA.
    #[must_use]
    pub const fn assignment(&self) -> &OriginalAssignmentV2 {
        &self.assignment
    }

    /// Returns the retained historical credential commitments DATA.
    #[must_use]
    pub const fn credential_commitments(&self) -> &Vec<[u8; 32]> {
        &self.credential_commitments
    }

    /// Borrows the original incarnation bytes.
    pub fn original_incarnation(&self) -> &[u8] {
        &self.original_incarnation
    }

    /// Compares the recipe digest before its complete canonical bytes.
    pub fn matches_recipe(&self, artifact: &crate::nix_build::VerifiedNixRecipeArtifactV2) -> bool {
        artifact.digest() == self.recipe_digest && artifact.canonical_bytes() == self.recipe
    }

    /// Commits the complete original presentation transcript.
    pub fn original_presentation_commitment(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(b"aos.sandbox.nix.original-start-presentation.v1\0")
            .chain_update((self.original_resource_version.len() as u64).to_be_bytes())
            .chain_update(&self.original_resource_version)
            .chain_update(&self.original_incarnation)
            .chain_update(self.original_generation.to_be_bytes())
            .finalize()
            .into()
    }

    /// Borrows the exact nested plain historical context bytes.
    pub fn ordinary_effect(&self) -> &[u8] {
        &self.ordinary_effect
    }

    /// Returns the retained original operation identity.
    pub fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the original idempotency request commitment.
    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Borrows the complete original desired record key and value.
    pub fn desired(&self) -> (&[u8], &[u8]) {
        (&self.desired_key, &self.desired_value)
    }

    /// Returns the generation preceding the historical Start mutation.
    pub fn original_generation(&self) -> u64 {
        self.original_generation
    }

    /// Borrows the exact original assignment bytes as current-Nix comparison DATA.
    ///
    /// This supplies no live assignment, lease, Start or resource-bank authority.
    pub fn original_assignment_manifest_data_v1(&self) -> &[u8] {
        &self.assignment.assignment
    }

    /// Encodes the complete canonical historical carrier.
    ///
    /// # Errors
    /// Preserves semantic validation, bounded JSON and length-conversion failures.
    pub fn encode(&self) -> Result<Vec<u8>, NixHistoryDataError> {
        self.validate()?;
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            limit: MAXIMUM_BYTES - HEADER_BYTES - DIGEST_BYTES,
        };
        serde_json::to_writer(&mut writer, self)?;
        let length = u32::try_from(writer.bytes.len()).map_err(|_| NixHistoryDataError::Invalid)?;

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

    /// Decodes recognized canonical historical carrier bytes without issuing authority.
    ///
    /// # Errors
    /// Refuses original framing, extent, checksum, JSON and canonical/semantic failures.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, NixHistoryDataError> {
        if !bytes.starts_with(MAGIC) {
            return Ok(None);
        }
        if !(HEADER_BYTES + DIGEST_BYTES..=MAXIMUM_BYTES).contains(&bytes.len())
            || bytes[8..10] != 2_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(NixHistoryDataError::Invalid);
        }
        let length_bytes = bytes[16..20]
            .try_into()
            .map_err(|_| NixHistoryDataError::Invalid)?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        let end = HEADER_BYTES
            .checked_add(length)
            .ok_or(NixHistoryDataError::Invalid)?;
        if end.checked_add(DIGEST_BYTES) != Some(bytes.len())
            || Sha256::new()
                .chain_update(DOMAIN)
                .chain_update(&bytes[..end])
                .finalize()
                .as_slice()
                != &bytes[end..]
        {
            return Err(NixHistoryDataError::Invalid);
        }

        let carrier: Self = serde_json::from_slice(&bytes[HEADER_BYTES..end])?;
        if carrier.encode()? != bytes {
            return Err(NixHistoryDataError::Invalid);
        }
        Ok(Some(carrier))
    }

    /// Checks the complete historical scalar and canonical context joins.
    ///
    /// # Errors
    /// Refuses the original malformed claims or semantic disagreement in original order.
    pub fn validate(&self) -> Result<(), NixHistoryDataError> {
        self.authority.validate()?;
        let context = PublicMutationContextV1::decode(&self.ordinary_effect)
            .map_err(|_| NixHistoryDataError::Invalid)?
            .ok_or(NixHistoryDataError::Invalid)?;
        if self.operation.as_bytes() == &[0; 16]
            || self.request_digest == [0; 32]
            || context.caller() != self.authority.holder
            || context.project() != self.authority.project
            || context.accepted_wall_seconds() != self.authority.accepted_wall_seconds
            || context.canonical_request() != self.authority.original_request
            || self.recipe.is_empty()
            || self.recipe.len() > crate::nix_build::NIX_REQUEST_MAXIMUM_BYTES_V2
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
            || [
                &self.assignment.binding,
                &self.assignment.assignment,
                &self.assignment.publication,
                &self.assignment.lease,
                &self.assignment.signature,
                &self.assignment.receipt,
                &self.assignment.receipt_signature,
            ]
            .iter()
            .any(|bytes| bytes.is_empty())
        {
            return Err(NixHistoryDataError::Invalid);
        }
        self.require_original_preconditions()?;
        Ok(())
    }

    fn require_original_preconditions(&self) -> Result<(), NixHistoryDataError> {
        use crate::public_api::projection::{
            PublicProjectionResourceV1, decode_checked_public_projection_v1,
        };

        let request = crate::public_api::mutation::ResolvedPublicMutationRequestV1::decode(
            &self.authority.original_request,
        )
        .map_err(|_| NixHistoryDataError::Invalid)?;
        let crate::public_api::request::DormantSandboxRequestKindV1::Start(request) =
            request.request()
        else {
            return Err(NixHistoryDataError::Invalid);
        };
        let mutation = request
            .mutation
            .as_option()
            .ok_or(NixHistoryDataError::Invalid)?;
        let projection =
            decode_checked_public_projection_v1(&self.desired_key, &self.desired_value)
                .map_err(|_| NixHistoryDataError::Invalid)?;
        let PublicProjectionResourceV1::Sandbox(sandbox) = projection.resource() else {
            return Err(NixHistoryDataError::Invalid);
        };
        let desired = sandbox
            .desired
            .as_option()
            .ok_or(NixHistoryDataError::Invalid)?;
        let next_generation = self
            .original_generation
            .checked_add(1)
            .ok_or(NixHistoryDataError::Invalid)?;
        let expected_version = super::compiler_resource_version(
            self.operation,
            crate::public_api::PublicOperationMethodV1::StartSandbox,
            next_generation,
            self.request_digest,
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
            || desired.lifecycle.as_known()
                != Some(aos_proto::aos::sandbox::v1::DesiredLifecycle::DESIRED_LIFECYCLE_RUNNING)
            || sandbox.updated_at.as_option().is_none_or(|time| {
                time.seconds != self.authority.accepted_wall_seconds || time.nanoseconds != 0
            })
        {
            return Err(NixHistoryDataError::Invalid);
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
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > self.limit)
        {
            return Err(io::Error::other(
                "retained Nix Start carrier exceeds its fixed bound",
            ));
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
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            limit: 4,
        };
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
        assert_eq!(
            NixStartAdmissionCarrierV2::decode(b"AOSPME01").unwrap(),
            None
        );
    }
}

#[cfg(test)]
mod assignment_tests {
    use super::*;

    // These buffers are historical DATA, not a publication, journal or owner.
    fn assignment_buffers() -> [Vec<u8>; 7] {
        std::array::from_fn(|index| vec![u8::try_from(index + 1).unwrap(); index + 2])
    }

    fn assignment_preimages(buffers: &[Vec<u8>; 7]) -> AssignmentPreimagesV2<'_> {
        AssignmentPreimagesV2 {
            bytes: buffers.each_ref().map(Vec::as_slice),
            binding_digest: ObjectDigest::from_bytes([8; 32]),
            publication_digest: ObjectDigest::from_bytes([9; 32]),
        }
    }

    #[test]
    fn borrowed_assignment_matches_the_complete_old_owned_layout() {
        let buffers = assignment_buffers();
        let original = OriginalAssignmentV2 {
            binding: buffers[0].clone(),
            binding_digest: ObjectDigest::from_bytes([8; 32]),
            assignment: buffers[1].clone(),
            publication: buffers[2].clone(),
            publication_digest: ObjectDigest::from_bytes([9; 32]),
            lease: buffers[3].clone(),
            signature: buffers[4].clone(),
            receipt: buffers[5].clone(),
            receipt_signature: buffers[6].clone(),
        };

        let owned = assignment_preimages(&buffers).into_owned();

        assert_eq!(owned, original);
        assert!(assignment_preimages(&buffers).matches_original(&original));
        assert_eq!(
            serde_json::to_vec(&owned).unwrap(),
            serde_json::to_vec(&original).unwrap(),
        );
    }

    #[test]
    fn borrowed_assignment_rejects_every_preimage_and_both_digest_substitutions() {
        let buffers = assignment_buffers();
        let original = assignment_preimages(&buffers).into_owned();

        for index in 0..buffers.len() {
            let mut substituted = buffers.clone();
            substituted[index][0] ^= 1;
            let view = assignment_preimages(&substituted);

            assert!(!view.matches_original(&original), "preimage {index}");
            assert_ne!(view.into_owned(), original, "preimage {index}");
        }

        let mut substituted = assignment_preimages(&buffers);
        substituted.binding_digest = ObjectDigest::from_bytes([10; 32]);
        assert!(!substituted.matches_original(&original));
        assert_ne!(substituted.into_owned(), original);

        let mut substituted = assignment_preimages(&buffers);
        substituted.publication_digest = ObjectDigest::from_bytes([10; 32]);
        assert!(!substituted.matches_original(&original));
        assert_ne!(substituted.into_owned(), original);
    }

    #[test]
    fn borrowed_assignment_compares_contents_not_buffer_identity() {
        let buffers = assignment_buffers();
        let original = assignment_preimages(&buffers).into_owned();
        let separate = buffers.clone();

        assert!(assignment_preimages(&separate).matches_original(&original));
        for (left, right) in buffers.iter().zip(&separate) {
            assert_ne!(left.as_ptr(), right.as_ptr());
        }
    }

    #[test]
    fn borrowed_assignment_rejects_trailing_bytes_and_reordered_families() {
        let buffers = assignment_buffers();
        let original = assignment_preimages(&buffers).into_owned();

        for index in 0..buffers.len() {
            let mut extended = buffers.clone();
            extended[index].push(0);

            assert!(
                !assignment_preimages(&extended).matches_original(&original),
                "preimage {index}",
            );
        }

        let mut reordered = buffers;
        reordered.swap(3, 4);
        assert!(!assignment_preimages(&reordered).matches_original(&original));
    }

    #[test]
    fn assignment_bound_counts_all_seven_preimages_and_checked_overflow() {
        let exact = [MAXIMUM_BYTES - 6, 1, 1, 1, 1, 1, 1];

        assert!(require_assignment_preimage_lengths(exact).is_ok());
        for index in 0..exact.len() {
            let mut oversized = exact;
            oversized[index] += 1;

            assert!(
                require_assignment_preimage_lengths(oversized).is_err(),
                "preimage {index}"
            );
        }
        assert!(require_assignment_preimage_lengths([1, usize::MAX, 0, 0, 0, 0, 0]).is_err());
        assert!(require_assignment_preimage_lengths([usize::MAX, 0, 0, 0, 0, 0, 0]).is_err());
    }
}

#[cfg(test)]
mod coordinate_tests {
    use super::*;

    // These coordinates are historical DATA used only to exercise equality.
    // They construct neither a decision, a selector nor a continuation owner.
    fn original_coordinates() -> OriginalPublicMutationCoordinatesV2 {
        OriginalPublicMutationCoordinatesV2 {
            capability: [1; 16],
            revocation_scope: [2; 16],
            revocation_generation: 3,
            policy_digest: [4; 32],
            policy_generation: 5,
            controller: [6; 16],
            controller_generation: 7,
            capability_not_before: 8,
            capability_expires_at: 9,
            policy_not_before: 10,
            policy_expires_at: 11,
            channel_binding: [12; 32],
            session_commitment: [13; 32],
            authorization_revision: [14; 32],
        }
    }

    #[test]
    fn only_the_observation_revision_may_change() {
        let original = original_coordinates();
        let observed = OriginalPublicMutationCoordinatesV2 {
            authorization_revision: [15; 32],
            ..original
        };

        assert!(original.require_coordinate_identity(original).is_ok());
        assert!(original.require_coordinate_identity(observed).is_ok());
        assert_eq!(original.authorization_revision, [14; 32]);
    }

    #[test]
    fn every_other_original_authority_coordinate_stays_exact() {
        let original = original_coordinates();
        let substitutions = [
            OriginalPublicMutationCoordinatesV2 {
                capability: [15; 16],
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                revocation_scope: [15; 16],
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                revocation_generation: 15,
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                policy_digest: [15; 32],
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                policy_generation: 15,
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                controller: [15; 16],
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                controller_generation: 15,
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                capability_not_before: 15,
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                capability_expires_at: 15,
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                policy_not_before: 15,
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                policy_expires_at: 15,
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                channel_binding: [15; 32],
                ..original
            },
            OriginalPublicMutationCoordinatesV2 {
                session_commitment: [15; 32],
                ..original
            },
        ];

        for substitution in substitutions {
            assert!(original.require_coordinate_identity(substitution).is_err());
        }
    }
}

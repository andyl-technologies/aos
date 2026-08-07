//! Channel intent, signed frontier, and publication-placement gates.

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;

use super::change_request::{parse_verified_git_tag, GitObjectId, GitObjectProof};
use super::plan::HeadSeal;
use super::primitives::{ContentDigest, ControlError, Generation, Revision, StableId};
use super::signing::{
    KeyGenerationState, SigningKeyConsumer, SigningKeyGenerationContents, SigningKeyUsageContents,
    SigningPurpose, SigningUsageState,
};

/// The fixed number of signed channel partitions.
pub const CHANNEL_PARTITION_COUNT: usize = 256;

/// Evidence emitted only after cryptographic verification of an exact Git tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedTagEvidence {
    /// Verified signed tag object.
    pub tag_object: GitObjectId,
    /// Canonical raw annotated tag proof with recomputed object identity.
    pub tag_proof: GitObjectProof,
    /// Exact Git object named by the verified tag.
    pub target_object: GitObjectId,
    /// Digest of the canonical semantic claims recovered from the signed payload.
    pub signed_payload_digest: ContentDigest,
    /// Signing-key identity that verified the signature.
    pub signer_key_id: StableId,
    /// Typed usage through which the signer was authorized.
    pub signing_usage_id: StableId,
    /// Exact immutable key generation used for verification.
    pub signing_key_generation: Generation,
    /// Fingerprint of the exact parsed public key used for verification.
    pub public_key_fingerprint: ContentDigest,
    /// Canonical unpadded standard-base64 Ed25519 public key.
    pub public_key: String,
    /// Canonical unpadded standard-base64 Ed25519 signature over the claim digest.
    pub signature: String,
    /// Digest of the exact signature bytes.
    pub signature_digest: ContentDigest,
    /// Digest of the canonical inner Git-tag payload signed inside the tag.
    pub embedded_claim_digest: ContentDigest,
    /// Canonical unpadded base64 signature embedded in the raw Git tag.
    pub embedded_signature: String,
    /// Digest of the exact embedded signature bytes.
    pub embedded_signature_digest: ContentDigest,
    /// Digest of verifier, policy, and trust-roster evidence retained with the result.
    pub verification_evidence_digest: ContentDigest,
}

impl VerifiedTagEvidence {
    /// Re-verifies the retained Ed25519 signature and canonical encodings.
    ///
    /// The signed message is `aos-hub-channel-claim-v1\0` followed by the
    /// lowercase hexadecimal canonical claim digest.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input or digest error for malformed/non-canonical key
    /// or signature bytes, a fingerprint mismatch, or a failed signature.
    pub fn verify_signature(&self) -> Result<(), ControlError> {
        let expected_embedded_claim = ContentDigest::of_value(&(
            &self.target_object,
            &self.signer_key_id,
            &self.signing_usage_id,
            self.signing_key_generation,
            &self.public_key_fingerprint,
            &self.verification_evidence_digest,
        ))?;
        if self.embedded_claim_digest != expected_embedded_claim {
            return Err(ControlError::DigestMismatch);
        }
        if self.tag_proof.object_id != self.tag_object {
            return Err(ControlError::DigestMismatch);
        }
        let tag = parse_verified_git_tag(&self.tag_proof)?;
        if tag.tag_name != "aos-retained"
            || tag.target != self.target_object
            || tag.signer_key_id != self.signer_key_id
            || tag.signing_key_generation != self.signing_key_generation
            || tag.signed_claim_digest != self.embedded_claim_digest
            || tag.signature != self.embedded_signature
        {
            return Err(invalid(
                "tag_proof",
                "raw tag target and embedded signature must equal retained claims",
            ));
        }
        if self.public_key.len() != 43 || self.signature.len() != 86 {
            return Err(invalid(
                "signature",
                "Ed25519 evidence requires bounded canonical key and signature encodings",
            ));
        }
        let public_key = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&self.public_key)
            .map_err(|_| invalid("public_key", "must be canonical unpadded base64"))?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| invalid("public_key", "Ed25519 public keys must contain 32 bytes"))?;
        if base64::engine::general_purpose::STANDARD_NO_PAD.encode(public_key) != self.public_key
            || ContentDigest::of_bytes(public_key) != self.public_key_fingerprint
        {
            return Err(ControlError::DigestMismatch);
        }
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| invalid("public_key", "must encode a valid Ed25519 key"))?;

        let signature = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&self.signature)
            .map_err(|_| invalid("signature", "must be canonical unpadded base64"))?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| invalid("signature", "Ed25519 signatures must contain 64 bytes"))?;
        if base64::engine::general_purpose::STANDARD_NO_PAD.encode(signature) != self.signature
            || ContentDigest::of_bytes(signature) != self.signature_digest
        {
            return Err(ControlError::DigestMismatch);
        }
        let signature = Signature::from_bytes(&signature);
        let mut message = b"aos-hub-channel-claim-v1\0".to_vec();
        message.extend_from_slice(self.signed_payload_digest.as_str().as_bytes());
        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| invalid("signature", "does not verify the canonical claim digest"))?;

        let embedded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&self.embedded_signature)
            .map_err(|_| invalid("embedded_signature", "must be canonical unpadded base64"))?;
        let embedded: [u8; 64] = embedded.try_into().map_err(|_| {
            invalid(
                "embedded_signature",
                "Ed25519 signatures must contain 64 bytes",
            )
        })?;
        if base64::engine::general_purpose::STANDARD_NO_PAD.encode(embedded)
            != self.embedded_signature
            || ContentDigest::of_bytes(embedded) != self.embedded_signature_digest
        {
            return Err(ControlError::DigestMismatch);
        }
        let mut embedded_message = b"aos-hub-git-tag-v1\0".to_vec();
        embedded_message.extend_from_slice(self.embedded_claim_digest.as_str().as_bytes());
        verifying_key
            .verify_strict(&embedded_message, &Signature::from_bytes(&embedded))
            .map_err(|_| invalid("embedded_signature", "does not verify the raw tag claim"))
    }
}

/// One exact release selected for one signed channel partition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChannelPartitionTarget {
    /// Partition number in `0..=255`.
    pub partition: u16,
    /// Release stable identity.
    pub release_id: StableId,
    /// Digest of the immutable release manifest selected for this partition.
    pub release_manifest_digest: ContentDigest,
    /// Cryptographic evidence for the exact signed release-tag claims.
    pub verified_tag: VerifiedTagEvidence,
}

/// Immutable desired channel configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChannelIntentContents {
    /// Owning registry stable identity.
    pub registry_id: StableId,
    /// Canonical channel name.
    pub name: String,
    /// Whether new advances are allowed.
    pub active: bool,
    /// Signing-key usage binding stable identity.
    pub signing_usage_id: StableId,
    /// Exact signing-key generation for the next frontier.
    pub signing_key_generation: Generation,
    /// Minimum allowed monotonically increasing frontier ordinal.
    pub retention_floor_ordinal: u64,
}

/// One immutable channel-intent revision.
pub type ChannelIntentRevision = Revision<ChannelIntentContents>;

impl ChannelIntentContents {
    /// Validates a channel intent.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] unless `name` is a canonical lowercase
    /// channel slug.
    pub fn validate(&self) -> Result<(), ControlError> {
        let valid = !self.name.is_empty()
            && self.name.len() <= 64
            && self.name.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (byte == b'-' && index != 0 && index + 1 != self.name.len())
            });
        if !valid {
            return Err(invalid(
                "channel_name",
                "must be a canonical lowercase slug",
            ));
        }
        if self.registry_id.kind() != "registry" || self.signing_usage_id.kind() != "signing-usage"
        {
            return Err(invalid(
                "channel_intent",
                "registry and signing usage must use typed stable identities",
            ));
        }
        Ok(())
    }

    /// Derives the stable channel identity from registry identity and name.
    ///
    /// # Errors
    ///
    /// Returns a validation, canonical serialization, or stable-id error.
    pub fn stable_id(&self) -> Result<StableId, ControlError> {
        self.validate()?;
        let digest = ContentDigest::of_value(&(&self.registry_id, &self.name))?;
        StableId::new(format!("channel:{}", digest.as_str()))
    }
}

/// One immutable signed channel frontier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChannelFrontier {
    /// Registry whose channel namespace owns this frontier.
    pub registry_id: StableId,
    /// Stable channel identity derived from registry and channel name.
    pub channel_id: StableId,
    /// Monotonically increasing registry-local frontier ordinal.
    pub ordinal: u64,
    /// Exact signed frontier tag object.
    pub signed_frontier_tag: VerifiedTagEvidence,
    /// Complete ordered 256-partition release mapping.
    pub partitions: Vec<ChannelPartitionTarget>,
    /// Registry publication containing the frontier.
    pub publication_id: StableId,
    /// Digest of the immutable registry publication.
    pub publication_digest: ContentDigest,
    /// Exact write-authority revision under which this frontier was published.
    pub write_authority_head: HeadSeal,
    /// Exact authoritative mandatory-placement index resolved for publication.
    pub mandatory_placement_index_head: HeadSeal,
}

impl ChannelFrontier {
    /// Validates the complete signed partition mapping.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input, canonical-serialization, or digest mismatch
    /// error unless all 256 partitions appear once in order and every verified
    /// tag binds the exact registry, channel, release, signer, usage, and key.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.ordinal == 0 {
            return Err(invalid("frontier_ordinal", "must be positive"));
        }
        if self.partitions.len() != CHANNEL_PARTITION_COUNT
            || self
                .partitions
                .iter()
                .enumerate()
                .any(|(index, target)| usize::from(target.partition) != index)
        {
            return Err(invalid(
                "partitions",
                "must contain every partition 0 through 255 exactly once in order",
            ));
        }
        if self.registry_id.kind() != "registry"
            || self.channel_id.kind() != "channel"
            || self.publication_id.kind() != "publication"
            || self.write_authority_head.stable_id.kind() != "write-authority"
            || self.mandatory_placement_index_head.stable_id
                != mandatory_placement_index_id(&self.registry_id)?
            || self.signed_frontier_tag.signer_key_id.kind() != "signing-key"
            || self.signed_frontier_tag.signing_usage_id.kind() != "signing-usage"
        {
            return Err(invalid(
                "frontier_identity",
                "frontier, publication, signer, and usage identities must be typed",
            ));
        }
        self.signed_frontier_tag.verify_signature()?;
        for target in &self.partitions {
            if target.release_id.kind() != "release"
                || target.verified_tag.signer_key_id.kind() != "signing-key"
                || target.verified_tag.signing_usage_id.kind() != "signing-usage"
            {
                return Err(invalid(
                    "release_tag",
                    "every release tag must retain typed independent signing evidence",
                ));
            }
            target.verified_tag.verify_signature()?;
            let expected_release_claim = ContentDigest::of_value(&(
                &self.registry_id,
                &self.channel_id,
                target.partition,
                &target.release_id,
                &target.release_manifest_digest,
                &target.verified_tag.tag_object,
                &target.verified_tag.target_object,
                &target.verified_tag.signer_key_id,
                &target.verified_tag.signing_usage_id,
                target.verified_tag.signing_key_generation,
                &target.verified_tag.public_key_fingerprint,
                &target.verified_tag.verification_evidence_digest,
            ))?;
            if target.verified_tag.signed_payload_digest != expected_release_claim {
                return Err(ControlError::DigestMismatch);
            }
        }
        let expected_frontier_claim = self.claims_digest()?;
        if self.signed_frontier_tag.signed_payload_digest != expected_frontier_claim {
            return Err(ControlError::DigestMismatch);
        }
        Ok(())
    }

    fn claims_digest(&self) -> Result<ContentDigest, ControlError> {
        ContentDigest::of_value(&(
            &self.registry_id,
            &self.channel_id,
            self.ordinal,
            &self.signed_frontier_tag.tag_object,
            &self.signed_frontier_tag.target_object,
            &self.partitions,
            &self.publication_id,
            &self.write_authority_head,
            &self.mandatory_placement_index_head,
            &self.signed_frontier_tag.signer_key_id,
            &self.signed_frontier_tag.signing_usage_id,
            self.signed_frontier_tag.signing_key_generation,
            &self.signed_frontier_tag.public_key_fingerprint,
            &self.signed_frontier_tag.verification_evidence_digest,
        ))
    }

    /// Returns the digest of the complete signed frontier contents.
    ///
    /// # Errors
    ///
    /// Returns a frontier validation or canonical serialization error.
    pub fn digest(&self) -> Result<ContentDigest, ControlError> {
        self.validate()?;
        ContentDigest::of_value(self)
    }
}

/// Exact registry publication contents sealed into a channel advance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RegistryPublicationEvidence {
    /// Registry owning the publication.
    pub registry_id: StableId,
    /// Stable publication identity.
    pub publication_id: StableId,
    /// Exact published Git commit.
    pub commit: GitObjectId,
    /// Digest of the complete canonical publication contents.
    pub publication_digest: ContentDigest,
    /// Complete strictly sorted Git object set required by this publication.
    pub git_objects: Vec<GitObjectId>,
    /// Complete strictly sorted object digest set in this publication.
    pub object_digests: Vec<ContentDigest>,
    /// Digest of the complete immutable Git/content object manifest.
    pub object_manifest_digest: ContentDigest,
}

impl RegistryPublicationEvidence {
    fn validate(&self) -> Result<(), ControlError> {
        if self.registry_id.kind() != "registry"
            || self.publication_id.kind() != "publication"
            || self.git_objects.is_empty()
            || self.object_digests.is_empty()
            || self.git_objects.len() > 65_536
            || self.object_digests.len() > 65_536
            || self.git_objects.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .object_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .git_objects
                .iter()
                .any(|object| object.algorithm() != self.commit.algorithm())
        {
            return Err(invalid(
                "publication",
                "must use typed identities and a bounded canonical object set",
            ));
        }
        if ContentDigest::of_value(&(&self.git_objects, &self.object_digests))?
            != self.object_manifest_digest
            || ContentDigest::of_value(&(
                &self.registry_id,
                &self.publication_id,
                &self.commit,
                &self.object_manifest_digest,
            ))? != self.publication_digest
        {
            return Err(ControlError::DigestMismatch);
        }
        Ok(())
    }
}

/// Exact write-authority revision sealed into an advance plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WriteAuthorityEvidence {
    /// Stable write-authority identity.
    pub authority_id: StableId,
    /// Registry controlled by this authority.
    pub registry_id: StableId,
    /// Exact authority generation.
    pub generation: Generation,
    /// Current primary placement identity.
    pub primary_placement_id: StableId,
    /// Authoritative exact current revision head.
    pub head: HeadSeal,
}

/// Exact successful publication observation at one mandatory placement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlacementPublicationEvidence {
    /// Mandatory placement identity.
    pub placement_id: StableId,
    /// Exact candidate publication present at the placement.
    pub publication: RegistryPublicationEvidence,
    /// Digest of the placement's immutable physical object manifest.
    pub physical_manifest_digest: ContentDigest,
    /// Complete strictly sorted physical Git object set observed.
    pub physical_git_objects: Vec<GitObjectId>,
    /// Complete strictly sorted physical object digest set observed.
    pub physical_object_digests: Vec<ContentDigest>,
    /// Write-authority generation fenced during publication.
    pub authority_generation: Generation,
}

/// One exact placement required by authoritative publication policy resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MandatoryPlacementRequirement {
    /// Required placement identity.
    pub placement_id: StableId,
    /// Exact current placement revision from which eligibility was resolved.
    pub placement_head: HeadSeal,
    /// Exact active policy revision requiring this placement.
    pub policy_head: HeadSeal,
}

/// Exact active signing usage and immutable key generation used for verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SigningBindingEvidence {
    /// Exact signing-key identity resolved through the usage binding.
    pub signer_key_id: StableId,
    /// Exact signing usage identity.
    pub signing_usage_id: StableId,
    /// Exact immutable signing-key generation.
    pub signing_key_generation: Generation,
    /// Fingerprint of the exact parsed public key.
    pub public_key_fingerprint: ContentDigest,
    /// Authoritative exact signing-usage head.
    pub signing_usage_head: HeadSeal,
    /// Exact current signing-usage contents.
    pub signing_usage: SigningKeyUsageContents,
    /// Authoritative exact signing-key generation head.
    pub signing_key_head: HeadSeal,
    /// Exact current signing-key generation contents.
    pub signing_key: SigningKeyGenerationContents,
}

/// Physical publication facts that an advance plan must seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChannelPublicationGate {
    /// Exact current write-authority revision.
    write_authority: WriteAuthorityEvidence,
    /// Exact current registry publication contents.
    base_publication: RegistryPublicationEvidence,
    /// Exact candidate registry publication contents.
    candidate_publication: RegistryPublicationEvidence,
    /// Exact ChannelFrontier signing usage and key revision.
    frontier_signing: SigningBindingEvidence,
    /// Independent exact registry-publication signing usage and key revision.
    publication_signing: SigningBindingEvidence,
    /// Complete required placement-policy resolution, strictly placement sorted.
    mandatory_placements: Vec<MandatoryPlacementRequirement>,
    /// Authoritative current head of the complete mandatory-placement index.
    mandatory_placement_index_head: HeadSeal,
    /// Strictly placement-id-sorted mandatory publication observations.
    required_placements: Vec<PlacementPublicationEvidence>,
    /// Digest of the physical manifest for every mandatory placement.
    required_placement_manifest_digest: ContentDigest,
}

impl ChannelPublicationGate {
    /// Validates mandatory placement and key-generation seals.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] for an empty, unordered, duplicate
    /// placement set or a key generation that differs from channel intent.
    pub fn validate(&self, intent: &ChannelIntentContents) -> Result<(), ControlError> {
        if self.mandatory_placements.is_empty()
            || self.mandatory_placements.len() > 256
            || self
                .mandatory_placements
                .windows(2)
                .any(|pair| pair[0].placement_id >= pair[1].placement_id)
            || self.required_placements.is_empty()
            || self.required_placements.len() > 256
            || self
                .required_placements
                .windows(2)
                .any(|pair| pair[0].placement_id >= pair[1].placement_id)
        {
            return Err(invalid(
                "required_placements",
                "must be non-empty, strictly sorted, and duplicate-free",
            ));
        }
        if self.write_authority.authority_id.kind() != "write-authority"
            || self.write_authority.registry_id != intent.registry_id
            || self.write_authority.primary_placement_id.kind() != "placement"
            || self.base_publication.registry_id != intent.registry_id
            || self.candidate_publication.registry_id != intent.registry_id
            || self.base_publication.publication_id.kind() != "publication"
            || self.candidate_publication.publication_id.kind() != "publication"
        {
            return Err(invalid(
                "publication_identity",
                "authority and publications must use typed identities for the intent registry",
            ));
        }
        self.base_publication.validate()?;
        self.candidate_publication.validate()?;
        for requirement in &self.mandatory_placements {
            if requirement.placement_id.kind() != "placement"
                || requirement.placement_head.stable_id != requirement.placement_id
                || requirement.policy_head.stable_id.kind() != "placement-policy"
            {
                return Err(invalid(
                    "mandatory_placements",
                    "every requirement must bind exact typed placement and policy heads",
                ));
            }
        }
        let mandatory_digest = ContentDigest::of_value(&self.mandatory_placements)?;
        if self.mandatory_placement_index_head.stable_id
            != mandatory_placement_index_id(&intent.registry_id)?
            || self.mandatory_placement_index_head.content_digest != mandatory_digest
            || !self
                .mandatory_placements
                .iter()
                .map(|requirement| &requirement.placement_id)
                .eq(self
                    .required_placements
                    .iter()
                    .map(|placement| &placement.placement_id))
        {
            return Err(invalid(
                "mandatory_placement_index_head",
                "observations must exactly cover the authoritative required-placement index",
            ));
        }
        let authority_contents = (
            &self.write_authority.authority_id,
            &self.write_authority.registry_id,
            self.write_authority.generation,
            &self.write_authority.primary_placement_id,
        );
        if self.write_authority.head.stable_id != self.write_authority.authority_id
            || self.write_authority.head.generation != self.write_authority.generation
            || self.write_authority.head.content_digest
                != ContentDigest::of_value(&authority_contents)?
        {
            return Err(ControlError::DigestMismatch);
        }
        for placement in &self.required_placements {
            if placement.placement_id.kind() != "placement"
                || placement.publication != self.candidate_publication
                || placement.authority_generation != self.write_authority.generation
                || placement.physical_git_objects != self.candidate_publication.git_objects
                || placement.physical_object_digests != self.candidate_publication.object_digests
                || ContentDigest::of_value(&(
                    &placement.physical_git_objects,
                    &placement.physical_object_digests,
                ))? != placement.physical_manifest_digest
            {
                return Err(invalid(
                    "required_placements",
                    "every placement must prove the exact candidate under the sealed authority generation",
                ));
            }
        }
        if !self
            .required_placements
            .iter()
            .any(|placement| placement.placement_id == self.write_authority.primary_placement_id)
        {
            return Err(invalid(
                "required_placements",
                "must include the exact primary write-authority placement",
            ));
        }
        if ContentDigest::of_value(&self.required_placements)?
            != self.required_placement_manifest_digest
        {
            return Err(ControlError::DigestMismatch);
        }
        if self.frontier_signing.signing_key_generation != intent.signing_key_generation
            || self.frontier_signing.signing_usage_id != intent.signing_usage_id
        {
            return Err(invalid(
                "signing_key_generation",
                "must equal the generation pinned by channel intent",
            ));
        }
        let channel_id = intent.stable_id()?;
        self.frontier_signing.validate(
            &SigningKeyConsumer::Channel(channel_id),
            SigningPurpose::ChannelFrontier,
        )?;
        self.publication_signing.validate(
            &SigningKeyConsumer::Registry(intent.registry_id.clone()),
            SigningPurpose::RegistryPublication,
        )?;
        Ok(())
    }
}

impl SigningBindingEvidence {
    fn validate(
        &self,
        consumer: &SigningKeyConsumer,
        purpose: SigningPurpose,
    ) -> Result<(), ControlError> {
        self.signing_usage.validate()?;
        self.signing_key.validate_new()?;
        if self.signer_key_id.kind() != "signing-key"
            || self.signing_usage_head.stable_id != self.signing_usage_id
            || self.signing_usage_head.content_digest
                != ContentDigest::of_value(&self.signing_usage)?
            || self.signing_usage.stable_id()? != self.signing_usage_id
            || &self.signing_usage.consumer != consumer
            || self.signing_usage.purpose != purpose
            || self.signing_usage.signing_key_id != self.signer_key_id
            || self.signing_usage.signing_key_generation != self.signing_key_generation
            || self.signing_usage.state != SigningUsageState::Active
            || self.signing_key_head.stable_id != self.signer_key_id
            || self.signing_key_head.generation != self.signing_key_generation
            || self.signing_key_head.content_digest != ContentDigest::of_value(&self.signing_key)?
            || self.signing_key.state != KeyGenerationState::Active
            || self.signing_key.public_key_fingerprint != self.public_key_fingerprint
        {
            return Err(invalid(
                "signing_evidence",
                "must bind the exact active usage and key-generation revisions",
            ));
        }
        Ok(())
    }
}

/// Exact semantic inputs for a reviewed channel advance operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChannelAdvance {
    /// Current signed frontier.
    pub current: ChannelFrontier,
    /// Proposed next signed frontier.
    pub candidate: ChannelFrontier,
    /// Physical and signing facts sealed for publication.
    pub publication_gate: ChannelPublicationGate,
}

impl ChannelAdvance {
    /// Validates monotonic frontier and all publication prerequisites.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Invalid`] when the channel is inactive, the
    /// frontier does not advance monotonically, the retention floor would be
    /// violated, the candidate does not name the sealed publication, or a
    /// publication gate is incomplete.
    pub fn validate(&self, intent: &ChannelIntentContents) -> Result<(), ControlError> {
        intent.validate()?;
        self.current.validate()?;
        self.candidate.validate()?;
        self.publication_gate.validate(intent)?;
        if !intent.active {
            return Err(invalid("active", "inactive channels cannot advance"));
        }
        let channel_id = intent.stable_id()?;
        if self.current.registry_id != intent.registry_id
            || self.candidate.registry_id != intent.registry_id
            || self.current.channel_id != channel_id
            || self.candidate.channel_id != channel_id
        {
            return Err(invalid(
                "channel_identity",
                "current and candidate frontiers must name the exact intent registry and channel",
            ));
        }
        let candidate_evidence = &self.candidate.signed_frontier_tag;
        if candidate_evidence.signer_key_id != self.publication_gate.frontier_signing.signer_key_id
            || candidate_evidence.signing_usage_id
                != self.publication_gate.frontier_signing.signing_usage_id
            || candidate_evidence.signing_key_generation
                != self
                    .publication_gate
                    .frontier_signing
                    .signing_key_generation
            || candidate_evidence.public_key_fingerprint
                != self
                    .publication_gate
                    .frontier_signing
                    .public_key_fingerprint
        {
            return Err(invalid(
                "frontier_signature",
                "candidate verification evidence must match the sealed signer and usage",
            ));
        }
        for target in &self.candidate.partitions {
            let release = &target.verified_tag;
            if release.signer_key_id != self.publication_gate.publication_signing.signer_key_id
                || release.signing_usage_id
                    != self.publication_gate.publication_signing.signing_usage_id
                || release.signing_key_generation
                    != self
                        .publication_gate
                        .publication_signing
                        .signing_key_generation
                || release.public_key_fingerprint
                    != self
                        .publication_gate
                        .publication_signing
                        .public_key_fingerprint
            {
                return Err(invalid(
                    "release_signature",
                    "release tags must use the independent registry-publication signing binding",
                ));
            }
        }
        let publication = &self.publication_gate.candidate_publication;
        if candidate_evidence.target_object != publication.commit {
            return Err(invalid(
                "candidate_publication",
                "the signed frontier tag must target the exact candidate publication commit",
            ));
        }
        let required_git_objects = std::iter::once(&candidate_evidence.tag_object)
            .chain(std::iter::once(&candidate_evidence.target_object))
            .chain(self.candidate.partitions.iter().flat_map(|target| {
                [
                    &target.verified_tag.tag_object,
                    &target.verified_tag.target_object,
                ]
            }));
        if required_git_objects
            .into_iter()
            .any(|object| publication.git_objects.binary_search(object).is_err())
            || self.candidate.partitions.iter().any(|target| {
                publication
                    .object_digests
                    .binary_search(&target.release_manifest_digest)
                    .is_err()
            })
        {
            return Err(invalid(
                "candidate_publication",
                "publication and every mandatory placement must contain exact frontier/release tags, targets, and release manifests",
            ));
        }
        if self.candidate.write_authority_head != self.publication_gate.write_authority.head
            || self.candidate.mandatory_placement_index_head
                != self.publication_gate.mandatory_placement_index_head
        {
            return Err(invalid(
                "frontier_publication_claim",
                "signed frontier must claim the exact authority and mandatory-placement index heads",
            ));
        }
        if self.candidate.ordinal <= self.current.ordinal
            || self.candidate.ordinal < intent.retention_floor_ordinal
        {
            return Err(invalid(
                "frontier_ordinal",
                "must advance and remain at or above the retention floor",
            ));
        }
        if self.current.publication_id != self.publication_gate.base_publication.publication_id
            || self.current.publication_digest
                != self.publication_gate.base_publication.publication_digest
        {
            return Err(invalid(
                "base_publication",
                "current frontier differs from the sealed base publication",
            ));
        }
        if self.candidate.publication_id
            != self.publication_gate.candidate_publication.publication_id
            || self.candidate.publication_digest
                != self
                    .publication_gate
                    .candidate_publication
                    .publication_digest
        {
            return Err(invalid(
                "candidate_publication",
                "candidate frontier differs from the sealed candidate publication",
            ));
        }
        Ok(())
    }
}

fn invalid(field: &'static str, reason: &str) -> ControlError {
    ControlError::Invalid {
        field,
        reason: reason.into(),
    }
}

fn mandatory_placement_index_id(registry_id: &StableId) -> Result<StableId, ControlError> {
    StableId::new(format!(
        "mandatory-placement-index:{}",
        ContentDigest::of_value(registry_id)?.as_str()
    ))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Signer as _;

    use super::*;
    use crate::retained_control::change_request::GitObjectKind;
    use crate::retained_control::primitives::ResourceVersion;
    use crate::retained_control::signing::{KeyCustody, SigningAlgorithm};

    fn oid(byte: char) -> GitObjectId {
        GitObjectId::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn intent() -> ChannelIntentContents {
        let registry_id = StableId::new("registry:main").unwrap();
        let channel_id = StableId::new(format!(
            "channel:{}",
            ContentDigest::of_value(&(&registry_id, "stable"))
                .unwrap()
                .as_str()
        ))
        .unwrap();
        let usage = SigningKeyUsageContents {
            consumer: SigningKeyConsumer::Channel(channel_id),
            purpose: SigningPurpose::ChannelFrontier,
            signing_key_id: StableId::new("signing-key:release").unwrap(),
            signing_key_generation: Generation::new(2).unwrap(),
            state: SigningUsageState::Active,
        };
        ChannelIntentContents {
            registry_id,
            name: "stable".into(),
            active: true,
            signing_usage_id: usage.stable_id().unwrap(),
            signing_key_generation: Generation::new(2).unwrap(),
            retention_floor_ordinal: 2,
        }
    }

    fn evidence(
        byte: char,
        signed_payload_digest: ContentDigest,
        signer_key_id: StableId,
        signing_usage_id: StableId,
        signing_key_generation: Generation,
        seed: u8,
    ) -> VerifiedTagEvidence {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let public_key = base64::engine::general_purpose::STANDARD_NO_PAD.encode(public_key_bytes);
        let mut message = b"aos-hub-channel-claim-v1\0".to_vec();
        message.extend_from_slice(signed_payload_digest.as_str().as_bytes());
        let signature_bytes = signing_key.sign(&message).to_bytes();
        let signature = base64::engine::general_purpose::STANDARD_NO_PAD.encode(signature_bytes);
        let target_object = oid(if byte == 'a' { 'c' } else { 'd' });
        let public_key_fingerprint = ContentDigest::of_bytes(public_key_bytes);
        let verification_evidence_digest = ContentDigest::of_bytes(format!("proof-{byte}"));
        let embedded_claim_digest = ContentDigest::of_value(&(
            &target_object,
            &signer_key_id,
            &signing_usage_id,
            signing_key_generation,
            &public_key_fingerprint,
            &verification_evidence_digest,
        ))
        .unwrap();
        let mut embedded_message = b"aos-hub-git-tag-v1\0".to_vec();
        embedded_message.extend_from_slice(embedded_claim_digest.as_str().as_bytes());
        let embedded_signature_bytes = signing_key.sign(&embedded_message).to_bytes();
        let embedded_signature =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(embedded_signature_bytes);
        let raw_tag = format!(
            "object {}\ntype commit\ntag aos-retained\ntagger AOS <aos@example.test> 1 +0000\n\naos-signer-key {}\naos-signing-generation {}\naos-signed-claim {}\naos-signature {}\n",
            target_object.as_str().split_once(':').unwrap().1,
            signer_key_id,
            signing_key_generation.get(),
            embedded_claim_digest.as_str(),
            embedded_signature,
        );
        let tag_proof =
            GitObjectProof::from_raw("sha256", GitObjectKind::Tag, raw_tag.as_bytes()).unwrap();
        VerifiedTagEvidence {
            tag_object: tag_proof.object_id.clone(),
            tag_proof,
            target_object,
            signed_payload_digest,
            signer_key_id,
            signing_usage_id,
            signing_key_generation,
            public_key_fingerprint,
            public_key,
            signature,
            signature_digest: ContentDigest::of_bytes(signature_bytes),
            embedded_claim_digest,
            embedded_signature,
            embedded_signature_digest: ContentDigest::of_bytes(embedded_signature_bytes),
            verification_evidence_digest,
        }
    }

    fn frontier_evidence(byte: char, digest: ContentDigest) -> VerifiedTagEvidence {
        evidence(
            byte,
            digest,
            StableId::new("signing-key:release").unwrap(),
            intent().signing_usage_id,
            Generation::new(2).unwrap(),
            7,
        )
    }

    fn publication_usage(intent: &ChannelIntentContents) -> SigningKeyUsageContents {
        SigningKeyUsageContents {
            consumer: SigningKeyConsumer::Registry(intent.registry_id.clone()),
            purpose: SigningPurpose::RegistryPublication,
            signing_key_id: StableId::new("signing-key:registry").unwrap(),
            signing_key_generation: Generation::new(4).unwrap(),
            state: SigningUsageState::Active,
        }
    }

    fn release_evidence(
        intent: &ChannelIntentContents,
        byte: char,
        digest: ContentDigest,
    ) -> VerifiedTagEvidence {
        let usage = publication_usage(intent);
        evidence(
            byte,
            digest,
            usage.signing_key_id.clone(),
            usage.stable_id().unwrap(),
            usage.signing_key_generation,
            9,
        )
    }

    fn frontier(
        intent: &ChannelIntentContents,
        ordinal: u64,
        publication: &str,
        byte: char,
    ) -> ChannelFrontier {
        let channel_id = intent.stable_id().unwrap();
        let write_authority = authority_evidence(intent);
        let mandatory_placement_index_head = mandatory_placement_index_head(intent);
        let mut frontier = ChannelFrontier {
            registry_id: intent.registry_id.clone(),
            channel_id,
            ordinal,
            signed_frontier_tag: frontier_evidence(
                byte,
                ContentDigest::of_bytes("pending-frontier"),
            ),
            partitions: (0_u16..=255)
                .map(|partition| ChannelPartitionTarget {
                    partition,
                    release_id: StableId::new(format!("release:{partition}")).unwrap(),
                    release_manifest_digest: ContentDigest::of_bytes(format!(
                        "release-manifest-{partition}"
                    )),
                    verified_tag: release_evidence(
                        intent,
                        byte,
                        ContentDigest::of_bytes("pending-release"),
                    ),
                })
                .collect(),
            publication_id: StableId::new(publication).unwrap(),
            publication_digest: ContentDigest::of_bytes(publication),
            write_authority_head: write_authority.head,
            mandatory_placement_index_head,
        };
        for target in &mut frontier.partitions {
            let signed_payload_digest = ContentDigest::of_value(&(
                &frontier.registry_id,
                &frontier.channel_id,
                target.partition,
                &target.release_id,
                &target.release_manifest_digest,
                &target.verified_tag.tag_object,
                &target.verified_tag.target_object,
                &target.verified_tag.signer_key_id,
                &target.verified_tag.signing_usage_id,
                target.verified_tag.signing_key_generation,
                &target.verified_tag.public_key_fingerprint,
                &target.verified_tag.verification_evidence_digest,
            ))
            .unwrap();
            target.verified_tag = release_evidence(intent, byte, signed_payload_digest);
        }
        let frontier_claims_digest = frontier.claims_digest().unwrap();
        frontier.signed_frontier_tag = frontier_evidence(byte, frontier_claims_digest);
        frontier
    }

    fn publication(frontier: &ChannelFrontier, byte: char) -> RegistryPublicationEvidence {
        let mut git_objects = vec![
            frontier.signed_frontier_tag.tag_object.clone(),
            frontier.signed_frontier_tag.target_object.clone(),
        ];
        git_objects.extend(frontier.partitions.iter().flat_map(|target| {
            [
                target.verified_tag.tag_object.clone(),
                target.verified_tag.target_object.clone(),
            ]
        }));
        git_objects.sort();
        git_objects.dedup();
        let mut object_digests = frontier
            .partitions
            .iter()
            .map(|target| target.release_manifest_digest.clone())
            .collect::<Vec<_>>();
        object_digests.push(ContentDigest::of_bytes(format!("object-{byte}")));
        object_digests.sort();
        object_digests.dedup();
        let object_manifest_digest =
            ContentDigest::of_value(&(&git_objects, &object_digests)).unwrap();
        let commit = frontier.signed_frontier_tag.target_object.clone();
        let publication_digest = ContentDigest::of_value(&(
            &frontier.registry_id,
            &frontier.publication_id,
            &commit,
            &object_manifest_digest,
        ))
        .unwrap();
        RegistryPublicationEvidence {
            registry_id: frontier.registry_id.clone(),
            publication_id: frontier.publication_id.clone(),
            commit,
            publication_digest,
            git_objects,
            object_digests,
            object_manifest_digest,
        }
    }

    fn resign_frontier(frontier: &mut ChannelFrontier, byte: char) {
        let frontier_claims_digest = frontier.claims_digest().unwrap();
        frontier.signed_frontier_tag = frontier_evidence(byte, frontier_claims_digest);
    }

    fn publication_gate(
        intent: &ChannelIntentContents,
        current: &RegistryPublicationEvidence,
        candidate: &RegistryPublicationEvidence,
    ) -> ChannelPublicationGate {
        let write_authority = authority_evidence(intent);
        let authority_generation = write_authority.generation;
        let primary_placement_id = write_authority.primary_placement_id.clone();
        let physical_git_objects = candidate.git_objects.clone();
        let physical_object_digests = candidate.object_digests.clone();
        let placement = PlacementPublicationEvidence {
            placement_id: primary_placement_id.clone(),
            publication: candidate.clone(),
            physical_manifest_digest: ContentDigest::of_value(&(
                &physical_git_objects,
                &physical_object_digests,
            ))
            .unwrap(),
            physical_git_objects,
            physical_object_digests,
            authority_generation,
        };
        let required_placements = vec![placement];
        let frontier_usage = SigningKeyUsageContents {
            consumer: SigningKeyConsumer::Channel(intent.stable_id().unwrap()),
            purpose: SigningPurpose::ChannelFrontier,
            signing_key_id: StableId::new("signing-key:release").unwrap(),
            signing_key_generation: Generation::new(2).unwrap(),
            state: SigningUsageState::Active,
        };
        let publication_usage = publication_usage(intent);
        let mandatory_placements = mandatory_placements(intent);
        let mandatory_placement_index_head = mandatory_placement_index_head(intent);
        ChannelPublicationGate {
            write_authority,
            base_publication: current.clone(),
            candidate_publication: candidate.clone(),
            frontier_signing: signing_binding(frontier_usage, 7),
            publication_signing: signing_binding(publication_usage, 9),
            mandatory_placement_index_head,
            mandatory_placements,
            required_placement_manifest_digest: ContentDigest::of_value(&required_placements)
                .unwrap(),
            required_placements,
        }
    }

    fn mandatory_placements(intent: &ChannelIntentContents) -> Vec<MandatoryPlacementRequirement> {
        let primary_placement_id = authority_evidence(intent).primary_placement_id;
        vec![MandatoryPlacementRequirement {
            placement_id: primary_placement_id.clone(),
            placement_head: HeadSeal {
                stable_id: primary_placement_id,
                generation: Generation::new(1).unwrap(),
                content_digest: ContentDigest::of_bytes("placement-primary"),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
            policy_head: HeadSeal {
                stable_id: StableId::new("placement-policy:channel").unwrap(),
                generation: Generation::new(1).unwrap(),
                content_digest: ContentDigest::of_bytes("placement-policy"),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
        }]
    }

    fn mandatory_placement_index_head(intent: &ChannelIntentContents) -> HeadSeal {
        let mandatory_placements = mandatory_placements(intent);
        let mandatory_digest = ContentDigest::of_value(&mandatory_placements).unwrap();
        HeadSeal {
            stable_id: mandatory_placement_index_id(&intent.registry_id).unwrap(),
            generation: Generation::new(1).unwrap(),
            content_digest: mandatory_digest,
            resource_version: ResourceVersion::new(1).unwrap(),
        }
    }

    fn signing_binding(usage: SigningKeyUsageContents, seed: u8) -> SigningBindingEvidence {
        let public_key_bytes = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let signing_key = SigningKeyGenerationContents {
            algorithm: SigningAlgorithm::Ed25519,
            public_key: base64::engine::general_purpose::STANDARD_NO_PAD.encode(public_key_bytes),
            public_key_fingerprint: ContentDigest::of_bytes(public_key_bytes),
            custody: KeyCustody::External,
            state: KeyGenerationState::Active,
        };
        SigningBindingEvidence {
            signer_key_id: usage.signing_key_id.clone(),
            signing_usage_id: usage.stable_id().unwrap(),
            signing_key_generation: usage.signing_key_generation,
            public_key_fingerprint: signing_key.public_key_fingerprint.clone(),
            signing_usage_head: HeadSeal {
                stable_id: usage.stable_id().unwrap(),
                generation: Generation::new(1).unwrap(),
                content_digest: ContentDigest::of_value(&usage).unwrap(),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
            signing_key_head: HeadSeal {
                stable_id: usage.signing_key_id.clone(),
                generation: usage.signing_key_generation,
                content_digest: ContentDigest::of_value(&signing_key).unwrap(),
                resource_version: ResourceVersion::new(1).unwrap(),
            },
            signing_usage: usage,
            signing_key,
        }
    }

    fn authority_evidence(intent: &ChannelIntentContents) -> WriteAuthorityEvidence {
        let authority_id = StableId::new("write-authority:main").unwrap();
        let primary_placement_id = StableId::new("placement:primary").unwrap();
        let generation = Generation::new(3).unwrap();
        let content_digest = ContentDigest::of_value(&(
            &authority_id,
            &intent.registry_id,
            generation,
            &primary_placement_id,
        ))
        .unwrap();
        WriteAuthorityEvidence {
            head: HeadSeal {
                stable_id: authority_id.clone(),
                generation,
                content_digest,
                resource_version: ResourceVersion::new(1).unwrap(),
            },
            authority_id,
            registry_id: intent.registry_id.clone(),
            generation,
            primary_placement_id,
        }
    }

    #[test]
    fn a_frontier_requires_all_partitions() {
        let mut incomplete = frontier(&intent(), 1, "publication:one", 'a');
        incomplete.partitions.pop();
        assert!(incomplete.validate().is_err());
    }

    #[test]
    fn advance_is_bound_to_authority_key_and_physical_manifest() {
        let intent = intent();
        let mut current = frontier(&intent, 1, "publication:one", 'a');
        let mut candidate = frontier(&intent, 2, "publication:two", 'b');
        let current_publication = publication(&current, '1');
        let candidate_publication = publication(&candidate, '2');
        current.publication_digest = current_publication.publication_digest.clone();
        candidate.publication_digest = candidate_publication.publication_digest.clone();
        let publication_gate =
            publication_gate(&intent, &current_publication, &candidate_publication);
        candidate.write_authority_head = publication_gate.write_authority.head.clone();
        resign_frontier(&mut current, 'a');
        resign_frontier(&mut candidate, 'b');
        let advance = ChannelAdvance {
            publication_gate,
            current,
            candidate,
        };
        advance.validate(&intent).unwrap();
    }

    #[test]
    fn advance_rejects_authority_publication_or_placement_substitution() {
        let intent = intent();
        let mut current = frontier(&intent, 1, "publication:one", 'a');
        let mut candidate = frontier(&intent, 2, "publication:two", 'b');
        let current_publication = publication(&current, '1');
        let candidate_publication = publication(&candidate, '2');
        current.publication_digest = current_publication.publication_digest.clone();
        candidate.publication_digest = candidate_publication.publication_digest.clone();
        let candidate_gate =
            publication_gate(&intent, &current_publication, &candidate_publication);
        candidate.write_authority_head = candidate_gate.write_authority.head.clone();
        resign_frontier(&mut current, 'a');
        resign_frontier(&mut candidate, 'b');

        let make_advance = || ChannelAdvance {
            current: current.clone(),
            candidate: candidate.clone(),
            publication_gate: publication_gate(
                &intent,
                &current_publication,
                &candidate_publication,
            ),
        };

        let mut changed_generation = make_advance();
        changed_generation
            .publication_gate
            .write_authority
            .generation = Generation::new(4).unwrap();
        assert!(changed_generation.validate(&intent).is_err());

        let mut changed_publication = make_advance();
        changed_publication
            .publication_gate
            .candidate_publication
            .commit = oid('9');
        assert!(changed_publication.validate(&intent).is_err());

        let mut changed_placement = make_advance();
        changed_placement.publication_gate.required_placements[0].physical_object_digests[0] =
            ContentDigest::of_bytes("substituted");
        assert!(changed_placement.validate(&intent).is_err());

        let mut omitted_physical_object = make_advance();
        omitted_physical_object.publication_gate.required_placements[0]
            .physical_git_objects
            .pop();
        assert!(omitted_physical_object.validate(&intent).is_err());

        let mut forged_mandatory_index = make_advance();
        forged_mandatory_index.publication_gate.mandatory_placements[0]
            .policy_head
            .content_digest = ContentDigest::of_bytes("other-policy");
        assert!(forged_mandatory_index.validate(&intent).is_err());

        let mut omitted_release_manifest = make_advance();
        let omitted = omitted_release_manifest.candidate.partitions[0]
            .release_manifest_digest
            .clone();
        omitted_release_manifest
            .publication_gate
            .candidate_publication
            .object_digests
            .retain(|digest| digest != &omitted);
        assert!(omitted_release_manifest.validate(&intent).is_err());

        let mut substituted_release_signer = make_advance();
        let frontier_signer = substituted_release_signer
            .publication_gate
            .frontier_signing
            .signer_key_id
            .clone();
        substituted_release_signer.candidate.partitions[0]
            .verified_tag
            .signer_key_id = frontier_signer;
        assert!(substituted_release_signer.validate(&intent).is_err());

        let mut changed_usage_head = make_advance();
        changed_usage_head
            .publication_gate
            .frontier_signing
            .signing_usage_head
            .content_digest = ContentDigest::of_bytes("other-usage");
        assert!(changed_usage_head.validate(&intent).is_err());

        let mut changed_key_head = make_advance();
        changed_key_head
            .publication_gate
            .publication_signing
            .signing_key_head
            .content_digest = ContentDigest::of_bytes("other-key-generation");
        assert!(changed_key_head.validate(&intent).is_err());

        let mut changed_authority_claim = make_advance();
        changed_authority_claim
            .candidate
            .write_authority_head
            .resource_version = ResourceVersion::new(2).unwrap();
        assert!(changed_authority_claim.validate(&intent).is_err());

        let mut changed_placement_claim = make_advance();
        changed_placement_claim
            .candidate
            .mandatory_placement_index_head
            .content_digest = ContentDigest::of_bytes("other-placements");
        assert!(changed_placement_claim.validate(&intent).is_err());
    }

    #[test]
    fn release_or_frontier_claim_tampering_breaks_the_content_binding() {
        let intent = intent();
        let mut changed_release = frontier(&intent, 2, "publication:two", 'b');
        changed_release.partitions[7].release_manifest_digest = ContentDigest::of_bytes("tamper");
        assert!(matches!(
            changed_release.validate(),
            Err(ControlError::DigestMismatch)
        ));

        let mut changed_registry = frontier(&intent, 2, "publication:two", 'b');
        changed_registry.registry_id = StableId::new("registry:other").unwrap();
        assert!(matches!(
            changed_registry.validate(),
            Err(ControlError::DigestMismatch)
        ));

        let mut changed_signature = frontier(&intent, 2, "publication:two", 'b');
        changed_signature.signed_frontier_tag.signature = "a".repeat(86);
        assert!(changed_signature.validate().is_err());

        let mut changed_tag_object = frontier(&intent, 2, "publication:two", 'b');
        changed_tag_object.partitions[7].verified_tag.tag_object = oid('e');
        assert!(changed_tag_object.validate().is_err());

        let mut changed_raw_tag = frontier(&intent, 2, "publication:two", 'b');
        changed_raw_tag.partitions[7]
            .verified_tag
            .tag_proof
            .raw_base64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(b"other tag");
        assert!(changed_raw_tag.validate().is_err());

        let mut changed_verification = frontier(&intent, 2, "publication:two", 'b');
        changed_verification.partitions[7]
            .verified_tag
            .verification_evidence_digest = ContentDigest::of_bytes("other-verifier-evidence");
        assert!(changed_verification.validate().is_err());
    }
}

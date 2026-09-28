//! Typed Project V3 association of original inputs with a resolved Policy.
//!
//! The original public requested-policy descriptor still names portable Policy
//! CBOR. It does not name request-layer JSON. This profile binds that exact
//! descriptor to the publisher's original compiler provenance and independently
//! supplied typed project/request inputs. No inverse Policy conversion exists.
//!
//! ```text
//! AOSPPH03 | project[16] | source-generation:u64 | issued/expires:i64 |
//! publisher-generation:u64 | Policy-digest[32] | association-sha256[32] |
//! ancestry/deployment/cache/revocation[4][32] | deployment/project-key-generation:u64 |
//! Ed25519-signature[64]
//! ```
//!
//! A held Controller join and pinned project signature establish association
//! provenance only. Source genesis/floor, installed backend/catalog owners,
//! publication history, and the all-owner effect barrier remain independent.

use std::path::Path;

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::controller::ControllerRequestScopeV1;
use crate::controller_service::journal::production_journal_limits;
use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};
use crate::reconciler::EffectPlan;
use crate::{Journal, RecordNamespace};

use super::deployment_head::{SIGNER_PINS_KEY, decode_policy_signer_pins_v1};
use super::model::canonical_bytes;
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::{
    CompiledPublisherPolicyRevisionV2, CurrentCreatePolicySourceErrorV1,
    CurrentCreateProjectPolicySourceV1, PolicyCompilerInputV1, PolicyDeploymentHeadErrorV1,
    PolicyDeploymentInputProfileV2, PolicyDeploymentInputsV1, ProjectPolicyInputV1,
    RequestPolicyInputV1, RetainedPublisherCompilerOriginV3,
    current_parentless_create_project_source_for_operation_v1,
    verify_current_policy_deployment_profile_v2,
};

const MAGIC: &[u8; 8] = b"AOSPPH03";
const SIGNING_DOMAIN: &[u8] = b"aos.sandbox.policy-project-head.v3\0";
const ASSOCIATION_DOMAIN: &[u8] = b"aos.sandbox.policy-project-request-association.v3";
const PAYLOAD_BYTES: usize = 264;
/// Fixes the size of a signed Project V3 association packet.
pub const PROJECT_POLICY_ASSOCIATION_PACKET_BYTES_V3: usize = PAYLOAD_BYTES + 64;

/// Retains typed association bytes produced from actual compiler provenance.
///
/// This is not an admitted project source or a Root history/currentness proof.
pub struct ProjectPolicyAssociationV3 {
    project: ProjectId,
    generation: u64,
    publisher_generation: u64,
    policy_digest: ObjectDigest,
    canonical_bytes: Vec<u8>,
}

impl ProjectPolicyAssociationV3 {
    /// Associates exact compiled output with its original typed input roles.
    ///
    /// # Errors
    ///
    /// Rejects zero source generation, missing compiler provenance, substituted
    /// original target/input/output, or canonical serialization failure.
    pub fn from_compiled_revision(
        prepared: &CompiledPublisherPolicyRevisionV2,
        original_input: &PolicyCompilerInputV1,
        source_generation: u64,
    ) -> Result<Self, PolicyDeploymentHeadErrorV1> {
        if source_generation == 0 {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        let revision = prepared.revision();
        let origin = revision
            .compiler_origin()
            .ok_or(PolicyDeploymentHeadErrorV1::InvalidHead)?;
        origin.verify_original_derivation(original_input)?;
        Ok(Self {
            project: revision.project(),
            generation: source_generation,
            publisher_generation: revision.generation(),
            policy_digest: revision.descriptor().digest(),
            canonical_bytes: association_bytes(
                source_generation,
                revision.generation(),
                revision.descriptor(),
                origin,
                original_input,
            )?,
        })
    }

    /// Returns exact signed-association input bytes, not an authority token.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Signs the distinct V3 profile with the existing project role.
    ///
    /// Key parameters nominate no trust. A consumer must independently pin
    /// both generations and the actual project key in protected Root custody.
    /// The four heads are claims, not owner proofs. No defaults are inserted.
    ///
    /// # Errors
    ///
    /// Rejects an invalid interval, zero role generation, or sentinel head.
    pub fn sign(
        &self,
        issued_at: i64,
        expires_at: i64,
        prerequisite_claims: [ObjectDigest; 4],
        deployment_signer_generation: u64,
        project_signer_generation: u64,
        key: &SigningKey,
    ) -> Result<[u8; PROJECT_POLICY_ASSOCIATION_PACKET_BYTES_V3], PolicyDeploymentHeadErrorV1> {
        if issued_at >= expires_at
            || deployment_signer_generation == 0
            || project_signer_generation == 0
            || prerequisite_claims
                .iter()
                .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
        }
        let mut packet = Vec::with_capacity(PROJECT_POLICY_ASSOCIATION_PACKET_BYTES_V3);
        packet.extend_from_slice(MAGIC);
        packet.extend_from_slice(self.project.as_bytes());
        packet.extend_from_slice(&self.generation.to_be_bytes());
        packet.extend_from_slice(&issued_at.to_be_bytes());
        packet.extend_from_slice(&expires_at.to_be_bytes());
        packet.extend_from_slice(&self.publisher_generation.to_be_bytes());
        packet.extend_from_slice(self.policy_digest.as_bytes());
        packet.extend_from_slice(&Sha256::digest(&self.canonical_bytes));
        for digest in prerequisite_claims {
            packet.extend_from_slice(digest.as_bytes());
        }
        packet.extend_from_slice(&deployment_signer_generation.to_be_bytes());
        packet.extend_from_slice(&project_signer_generation.to_be_bytes());
        let mut signed = SIGNING_DOMAIN.to_vec();
        signed.extend_from_slice(&packet);
        packet.extend_from_slice(&key.sign(&signed).to_bytes());
        packet
            .try_into()
            .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)
    }
}

/// Borrows the actual Controller writer and original typed compiler inputs.
///
/// The value cannot escape its callback or acquire authority from cold record
/// data. The selected Create may have a different child from the explicit
/// original compiler target. It still requests the exact resolved Policy
/// descriptor whose protected revision retained those original inputs.
pub struct HeldCurrentCreatePolicyInputsV3<'held> {
    controller: &'held Journal,
    sequence: u64,
    source: CurrentCreateProjectPolicySourceV1,
    origin: RetainedPublisherCompilerOriginV3,
    original_input: &'held PolicyCompilerInputV1,
    directory: &'held Path,
}

impl HeldCurrentCreatePolicyInputsV3<'_> {
    /// Returns the genuine existing live Create selector observation.
    #[must_use]
    pub const fn source(&self) -> &CurrentCreateProjectPolicySourceV1 {
        &self.source
    }

    /// Returns the exact original typed project input, not inferred Policy.
    #[must_use]
    pub const fn project_input(&self) -> &ProjectPolicyInputV1 {
        self.original_input.project()
    }

    /// Returns the exact original typed request input, not user data or a grant.
    #[must_use]
    pub const fn request_input(&self) -> &RequestPolicyInputV1 {
        self.original_input.request()
    }

    /// Returns retained nonauthorizing provenance after exact recompilation.
    #[must_use]
    pub const fn origin(&self) -> &RetainedPublisherCompilerOriginV3 {
        &self.origin
    }

    /// Rechecks the retained Controller writer, physical names, and cut.
    ///
    /// # Errors
    ///
    /// Rejects changed journal names, protection, or snapshot sequence.
    pub fn recheck(&self) -> Result<(), CurrentCreatePolicySourceErrorV1> {
        require_controller_name_at(self.controller, self.directory)?;
        if self.controller.snapshot_sequence() != self.sequence {
            return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
        }
        Ok(())
    }
}

/// Holds the existing current Create selector and checks its original inputs.
///
/// Controller custody is acquired before any Source/Cache or Root-last work.
/// The callback receives only borrowed input association provenance. Public
/// Create selectors, compiler draft gates, and effective-policy rules are
/// unchanged; V1/V2 publisher records with no origin fail closed here.
///
/// # Errors
///
/// Rejects noncurrent Create, projection, descriptor, publisher, old missing
/// origin, original target/derivation mismatch, or changed names/cut.
#[allow(clippy::too_many_arguments)]
pub fn with_current_parentless_create_policy_inputs_v3<R>(
    controller: &mut Journal,
    operation: OperationId,
    project: ProjectId,
    scope: ControllerRequestScopeV1,
    plan: &EffectPlan,
    original_input: &PolicyCompilerInputV1,
    inspect: impl for<'held> FnOnce(&HeldCurrentCreatePolicyInputsV3<'held>) -> R,
) -> Result<R, CurrentCreatePolicySourceErrorV1> {
    with_current_inputs_at(
        controller,
        Path::new("/var/lib/aos/sandboxd"),
        operation,
        project,
        scope,
        plan,
        original_input,
        inspect,
    )
}

#[allow(clippy::too_many_arguments)]
fn with_current_inputs_at<R>(
    controller: &mut Journal,
    directory: &Path,
    operation: OperationId,
    project: ProjectId,
    scope: ControllerRequestScopeV1,
    plan: &EffectPlan,
    original_input: &PolicyCompilerInputV1,
    inspect: impl for<'held> FnOnce(&HeldCurrentCreatePolicyInputsV3<'held>) -> R,
) -> Result<R, CurrentCreatePolicySourceErrorV1> {
    require_controller_name_at(controller, directory)?;
    let source = current_parentless_create_project_source_for_operation_v1(
        controller, operation, project, scope, plan,
    )?;
    let revision = PublisherPolicyStore::load(controller, PublisherPolicyLimits::default())?
        .current_policy(project)?
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?;
    let origin = revision
        .compiler_origin()
        .ok_or(CurrentCreatePolicySourceErrorV1::NotCurrent)?
        .clone();
    if revision.generation() != source.policy_generation()
        || revision.descriptor().digest() != source.policy_digest()
        || revision.canonical_policy() != source.canonical_policy()
    {
        return Err(CurrentCreatePolicySourceErrorV1::NotCurrent);
    }
    origin.verify_original_derivation(original_input)?;
    let held = HeldCurrentCreatePolicyInputsV3 {
        sequence: controller.snapshot_sequence(),
        controller,
        source,
        origin,
        original_input,
        directory,
    };
    held.recheck()?;
    let result = inspect(&held);
    held.recheck()?;
    Ok(result)
}

/// Verifies Project V3 association under held Controller and fixed Root pins.
///
/// Root is acquired last by the caller. This check authenticates the current
/// deployment declarations and exact project signature role independently;
/// it does not append a project head, prove ancestry/floor, authorize catalogs
/// or installed backends, or mint publication/read/effect authority. AOSPKP01
/// has no independent deployment-role revocation head; none is invented here.
///
/// # Errors
///
/// Rejects legacy/malformed packets, expiry, key/generation rotation, stale
/// deployment head, substituted association/layers/output, or Controller heads.
pub fn verify_held_project_policy_association_v3(
    root: &mut Journal,
    held: &HeldCurrentCreatePolicyInputsV3<'_>,
    packet: &[u8],
    deployment_packet: &[u8],
    deployment_inputs: &PolicyDeploymentInputsV1<'_>,
    deployment_profile: &PolicyDeploymentInputProfileV2,
    now_unix_seconds: i64,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    held.recheck()
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let deployment = verify_current_policy_deployment_profile_v2(
        root,
        deployment_packet,
        deployment_inputs,
        deployment_profile,
        now_unix_seconds,
    )?;
    verify_association_at_held_cut(
        root,
        held,
        packet,
        deployment_profile,
        deployment.packet_digest(),
        now_unix_seconds,
    )?;
    root.require_protected_named_location(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        0,
        policy_authority_journal_limits(),
    )?;
    held.recheck()
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    Ok(())
}

fn verify_association_at_held_cut(
    root: &mut Journal,
    held: &HeldCurrentCreatePolicyInputsV3<'_>,
    packet: &[u8],
    deployment_profile: &PolicyDeploymentInputProfileV2,
    deployment_digest: ObjectDigest,
    now_unix_seconds: i64,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    held.recheck()
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let authority = root.claim_protected_authority(RecordNamespace::DesiredState)?;
    let pins = authority
        .get(SIGNER_PINS_KEY)?
        .ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let (deployment_generation, _, project_generation, project_key) =
        decode_policy_signer_pins_v1(pins)?;
    let expected_input = held.original_input;
    if expected_input.node() != deployment_profile.node()
        || expected_input.site() != deployment_profile.site()
        || expected_input.backend() != deployment_profile.backend()
        || expected_input.endpoints().entries() != deployment_profile.catalogs().endpoints()
        || expected_input.destinations().entries() != deployment_profile.catalogs().destinations()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let revision_descriptor = held.origin.output_descriptors()?[0].clone();
    let source_generation = read_u64(packet, 24)?;
    let association = association_bytes(
        source_generation,
        held.source.policy_generation(),
        &revision_descriptor,
        &held.origin,
        expected_input,
    )?;
    verify_packet(packet, &association, &project_key, now_unix_seconds)?;
    if read_u64(packet, 248)? != deployment_generation
        || read_u64(packet, 256)? != project_generation
        || packet.get(8..24) != Some(held.source.project().as_bytes())
        || read_u64(packet, 48)? != held.source.policy_generation()
        || packet.get(56..88) != Some(held.source.policy_digest().as_bytes())
        || packet.get(152..184) != Some(deployment_digest.as_bytes())
        || packet.get(184..216) != Some(held.source.cache_domain_head().as_bytes())
        || packet.get(216..248) != Some(held.source.revocation_head().as_bytes())
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    held.recheck()
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    Ok(())
}

fn association_bytes(
    generation: u64,
    publisher_generation: u64,
    policy: &aos_sandbox_core::ObjectDescriptor,
    origin: &RetainedPublisherCompilerOriginV3,
    input: &PolicyCompilerInputV1,
) -> Result<Vec<u8>, PolicyDeploymentHeadErrorV1> {
    if generation == 0 {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    canonical_bytes(
        ASSOCIATION_DOMAIN,
        &(
            3_u16,
            origin.project(),
            generation,
            publisher_generation,
            policy,
            origin.record_digest()?,
            origin.original_target(),
            origin.normalized_input(),
            input.project().descriptor(),
            input.request().descriptor(),
        ),
    )
    .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidHead)
}

fn verify_packet(
    packet: &[u8],
    association: &[u8],
    key: &VerifyingKey,
    now: i64,
) -> Result<(), PolicyDeploymentHeadErrorV1> {
    if packet.len() != PROJECT_POLICY_ASSOCIATION_PACKET_BYTES_V3
        || packet.get(..8) != Some(MAGIC)
        || packet.get(8..24) == Some(&[0; 16])
        || read_u64(packet, 24)? == 0
        || read_u64(packet, 48)? == 0
        || read_u64(packet, 248)? == 0
        || read_u64(packet, 256)? == 0
        || read_i64(packet, 32)? >= read_i64(packet, 40)?
        || read_i64(packet, 32)? > now
        || now >= read_i64(packet, 40)?
        || packet.get(88..120) != Some(Sha256::digest(association).as_slice())
        || packet[120..248]
            .chunks_exact(32)
            .any(|digest| digest == [0; 32])
    {
        return Err(PolicyDeploymentHeadErrorV1::InvalidHead);
    }
    let signature = Signature::from_bytes(&take(packet, PAYLOAD_BYTES)?);
    let mut signed = SIGNING_DOMAIN.to_vec();
    signed.extend_from_slice(&packet[..PAYLOAD_BYTES]);
    key.verify(&signed, &signature)
        .map_err(|_| PolicyDeploymentHeadErrorV1::InvalidSignature)
}

fn require_controller_name_at(
    controller: &Journal,
    directory: &Path,
) -> Result<(), CurrentCreatePolicySourceErrorV1> {
    let uid = controller.protected_owner_uid()?;
    #[cfg(test)]
    if directory != Path::new("/var/lib/aos/sandboxd") {
        controller.validate_held_protected_at_uid_for_test(directory, "controller.journal", uid)?;
        return Ok(());
    }
    controller.require_protected_named_location(
        directory,
        "controller.journal",
        uid,
        production_journal_limits(),
    )?;
    Ok(())
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PolicyDeploymentHeadErrorV1> {
    Ok(u64::from_be_bytes(take(bytes, offset)?))
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, PolicyDeploymentHeadErrorV1> {
    Ok(i64::from_be_bytes(take(bytes, offset)?))
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], PolicyDeploymentHeadErrorV1> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(N)
                    .ok_or(PolicyDeploymentHeadErrorV1::InvalidHead)?,
        )
        .and_then(|value| value.try_into().ok())
        .ok_or(PolicyDeploymentHeadErrorV1::InvalidHead)
}

#[cfg(test)]
pub(super) mod tests;

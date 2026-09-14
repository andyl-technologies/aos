//! Canonical codec for split upload-pack and receive-pack control envelopes.
//!
//! ```text
//! AOSGITC1 | version:1 | kind:1 | object-format:1 | exchange:16 |
//! principal:16 | channel-binding:32 | expiry:8 | input-limit:8 |
//! output-limit:8 | variant-body | record-digest:32
//! ```
//!
//! Upload variant bodies contain a complete immutable export, advertised refs,
//! graph evidence, and audience. Receive bodies contain current repository and
//! live fences, current refs, CAS transitions, post graph, quarantine, policy,
//! and atomic-CAS commitments. Decode preflights every nested count and length
//! before any allocation.

use aos_sandbox_core::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_core::{
    AssignmentEpoch, CacheDomainId, DesiredGeneration, IncarnationId, MediaType,
    NamespaceGeneration, ObjectDescriptor, ObjectDigest, PrincipalId, ProjectId, ResourceId,
    Revision, SandboxId,
};
use sha2::{Digest as _, Sha256};

use super::model::{
    cache_kind_code, git_ref_map_digest_v1, GitAdvertisedRefV1, GitAncestryReportV1,
    GitAtomicCasDigestV1, GitAudienceDigestV1, GitChannelBindingDigestV1, GitDescriptorRoleV1,
    GitDescriptorV1, GitExportGenerationDigestV1, GitExportGenerationV1, GitGraphCompletenessV1,
    GitGraphProofDigestV1, GitGraphValidatorEvidenceV1, GitModelError, GitObjectDatabaseDigestV1,
    GitObjectFormatV1, GitObjectGraphEvidenceV1, GitObjectIdV1, GitObjectInventoryDigestV1,
    GitPackIndexSetDigestV1, GitPhysicalObjectEnumerationV1, GitQuarantineDigestV1,
    GitReadAudienceV1, GitRefMapDigestV1, GitRefNameV1, GitRepositoryV1, GitTrustedValidatorV1,
    GitValidationPolicyDigestV1, GitValidatorTrustDigestV1, GitWholeObjectDatabaseV1,
    MAXIMUM_GIT_GRAPH_ROOTS, MAXIMUM_GIT_REF_BYTES,
};
use super::protocol::{
    GitExchangePlanV1, GitProtocolV2CapabilitiesDigestV1, GitProtocolV2CapabilityV1,
    GitProtocolV2ProfileV1, GitProtocolV2ServiceV1, GitReceiveFenceV1, GitReceivePlanV1,
    GitRefTransitionV1, GitUploadPlanV1, MAXIMUM_GIT_CONTROL_RECORD_BYTES,
    MAXIMUM_GIT_PROTOCOL_V2_CAPABILITIES, MAXIMUM_GIT_REF_TRANSITIONS,
};

const MAGIC: &[u8; 8] = b"AOSGITC1";
const DOMAIN: &[u8] = b"aos.sandbox.git.control-record.v1\0";
const VERSION: u16 = 1;
const COMMON_BYTES: usize = 100;
const AUDIENCE_BYTES: usize = 56;
const GRAPH_FIXED_BYTES: usize = 92;
const PHYSICAL_ENUMERATION_BYTES: usize = 80;
const RECEIVE_FIXED_BEFORE_REFS: usize = 120;
const DIGEST_BYTES: usize = 32;

#[derive(Clone, Copy)]
struct Preflight {
    kind: u8,
    format: GitObjectFormatV1,
}

/// Encodes one validated split Git exchange in exact v1 form.
///
/// # Errors
///
/// Returns [`GitModelError`] if a nested length is not representable, the
/// fixed record ceiling is exceeded, or allocation fails.
pub fn encode_git_exchange_plan_v1(plan: &GitExchangePlanV1) -> Result<Vec<u8>, GitModelError> {
    if let GitExchangePlanV1::Receive(receive) = plan {
        return encode_git_receive_plan_v1(receive);
    }
    let expected_length = exchange_encoded_length(plan)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_length)
        .map_err(|_| GitModelError::Allocation)?;
    match plan {
        GitExchangePlanV1::Upload(upload) => {
            encode_common(
                &mut bytes,
                1,
                upload.export().graph().format(),
                upload.exchange(),
                upload.principal(),
                upload.channel_binding(),
                upload.expires_at_unix_seconds(),
                upload.maximum_input_bytes(),
                upload.maximum_output_bytes(),
            );
            encode_protocol(&mut bytes, upload.protocol());
            encode_export(&mut bytes, upload.export());
        }
        GitExchangePlanV1::Receive(_) => return Err(GitModelError::InvalidModel),
    }
    let digest: [u8; 32] = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(&bytes)
        .finalize()
        .into();
    bytes.extend_from_slice(&digest);
    if bytes.len() != expected_length {
        return Err(GitModelError::InvalidModel);
    }
    Ok(bytes)
}

/// Encodes one borrowed receive-pack plan without cloning its bounded graph.
pub(super) fn encode_git_receive_plan_v1(
    receive: &GitReceivePlanV1,
) -> Result<Vec<u8>, GitModelError> {
    let expected_length = receive_exchange_encoded_length(receive)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_length)
        .map_err(|_| GitModelError::Allocation)?;
    encode_common(
        &mut bytes,
        2,
        receive.repository().format(),
        receive.exchange(),
        receive.principal(),
        receive.channel_binding(),
        receive.expires_at_unix_seconds(),
        receive.maximum_input_bytes(),
        receive.maximum_output_bytes(),
    );
    encode_protocol(&mut bytes, receive.protocol());
    encode_receive(&mut bytes, receive);
    let digest: [u8; 32] = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(&bytes)
        .finalize()
        .into();
    bytes.extend_from_slice(&digest);
    if bytes.len() != expected_length {
        return Err(GitModelError::InvalidModel);
    }
    Ok(bytes)
}

fn exchange_encoded_length(plan: &GitExchangePlanV1) -> Result<usize, GitModelError> {
    let protocol = match plan {
        GitExchangePlanV1::Upload(value) => value.protocol(),
        GitExchangePlanV1::Receive(value) => value.protocol(),
    };
    let protocol_length = 36_usize
        .checked_add(protocol.capabilities().len())
        .ok_or(GitModelError::InvalidModel)?;
    let payload_length = match plan {
        GitExchangePlanV1::Upload(value) => export_encoded_length(value.export())?,
        GitExchangePlanV1::Receive(value) => receive_payload_encoded_length(value)?,
    };
    COMMON_BYTES
        .checked_add(protocol_length)
        .and_then(|total| total.checked_add(payload_length))
        .and_then(|total| total.checked_add(DIGEST_BYTES))
        .filter(|total| *total <= MAXIMUM_GIT_CONTROL_RECORD_BYTES)
        .ok_or(GitModelError::InvalidModel)
}

fn receive_exchange_encoded_length(receive: &GitReceivePlanV1) -> Result<usize, GitModelError> {
    let protocol_length = 36_usize
        .checked_add(receive.protocol().capabilities().len())
        .ok_or(GitModelError::InvalidModel)?;
    COMMON_BYTES
        .checked_add(protocol_length)
        .and_then(|total| total.checked_add(receive_payload_encoded_length(receive).ok()?))
        .and_then(|total| total.checked_add(DIGEST_BYTES))
        .filter(|total| *total <= MAXIMUM_GIT_CONTROL_RECORD_BYTES)
        .ok_or(GitModelError::InvalidModel)
}

fn receive_payload_encoded_length(value: &GitReceivePlanV1) -> Result<usize, GitModelError> {
    let refs = refs_encoded_length(value.current_refs())?;
    let transitions = value
        .transitions()
        .iter()
        .try_fold(4_usize, |total, transition| {
            total
                .checked_add(172)?
                .checked_add(transition.name().as_bytes().len())
        })
        .ok_or(GitModelError::InvalidModel)?;
    let pre_database = whole_database_encoded_length(value.pre_database())?;
    let post_database = whole_database_encoded_length(value.post_database())?;
    let quarantine = descriptor_encoded_length(value.quarantine())?;
    120_usize
        .checked_add(refs)
        .and_then(|total| total.checked_add(transitions))
        .and_then(|total| total.checked_add(64))
        .and_then(|total| total.checked_add(pre_database))
        .and_then(|total| total.checked_add(post_database))
        .and_then(|total| total.checked_add(quarantine))
        .and_then(|total| total.checked_add(96))
        .ok_or(GitModelError::InvalidModel)
}

pub(super) fn export_encoded_length(value: &GitExportGenerationV1) -> Result<usize, GitModelError> {
    let descriptor = descriptor_encoded_length(value.bare_export())?;
    let database = whole_database_encoded_length(value.database())?;
    let refs = refs_encoded_length(value.refs())?;
    96_usize
        .checked_add(descriptor)
        .and_then(|total| total.checked_add(database))
        .and_then(|total| total.checked_add(refs))
        .and_then(|total| total.checked_add(32))
        .ok_or(GitModelError::InvalidModel)
}

pub(super) fn whole_database_encoded_length(
    value: &GitWholeObjectDatabaseV1,
) -> Result<usize, GitModelError> {
    336_usize
        .checked_add(
            value
                .graph()
                .roots()
                .len()
                .checked_mul(32)
                .ok_or(GitModelError::InvalidModel)?,
        )
        .and_then(|total| {
            total.checked_add(
                value
                    .validator()
                    .report()
                    .descriptor()
                    .media_type()
                    .as_str()
                    .len(),
            )
        })
        .ok_or(GitModelError::InvalidModel)
}

fn descriptor_encoded_length(value: &GitDescriptorV1) -> Result<usize, GitModelError> {
    44_usize
        .checked_add(value.descriptor().media_type().as_str().len())
        .ok_or(GitModelError::InvalidModel)
}

pub(super) fn refs_encoded_length(values: &[GitAdvertisedRefV1]) -> Result<usize, GitModelError> {
    values
        .iter()
        .try_fold(4_usize, |total, value| {
            total
                .checked_add(34)?
                .checked_add(value.name().as_bytes().len())
        })
        .ok_or(GitModelError::InvalidModel)
}

/// Decodes one exact, bounded split Git exchange plan.
///
/// # Errors
///
/// Returns [`GitModelError`] for preflight failure, allocation failure,
/// non-canonical refs/graph, a validator attestation different from
/// `trusted_validator`, invalid roles, derived commitment mismatch, or a record
/// digest mismatch.
pub fn decode_git_exchange_plan_v1(
    encoded: &[u8],
    trusted_validator: &GitTrustedValidatorV1,
) -> Result<GitExchangePlanV1, GitModelError> {
    let preflight = preflight(encoded)?;
    let (body, stored_digest) = encoded.split_at(encoded.len() - DIGEST_BYTES);
    let digest: [u8; 32] = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(body)
        .finalize()
        .into();
    if digest.as_slice() != stored_digest {
        return Err(GitModelError::CorruptEncoding);
    }

    let mut bytes = body;
    if take::<8>(&mut bytes)? != *MAGIC
        || u16::from_be_bytes(take(&mut bytes)?) != VERSION
        || take::<1>(&mut bytes)? != [preflight.kind]
        || take::<1>(&mut bytes)? != [preflight.format as u8]
    {
        return Err(GitModelError::CorruptEncoding);
    }
    let exchange = ResourceId::from_bytes(take(&mut bytes)?);
    let principal = PrincipalId::from_bytes(take(&mut bytes)?);
    let channel =
        GitChannelBindingDigestV1::from_stored(ObjectDigest::from_bytes(take(&mut bytes)?))?;
    let expiry = u64::from_be_bytes(take(&mut bytes)?);
    let input_limit = u64::from_be_bytes(take(&mut bytes)?);
    let output_limit = u64::from_be_bytes(take(&mut bytes)?);
    let protocol = decode_protocol(&mut bytes, preflight.format)?;
    let plan = match preflight.kind {
        1 => GitExchangePlanV1::Upload(
            GitUploadPlanV1::new(
                exchange,
                decode_export(&mut bytes, preflight.format, trusted_validator)?,
                protocol,
                principal,
                channel,
                expiry,
                input_limit,
                output_limit,
            )
            .map_err(|_| GitModelError::CorruptEncoding)?,
        ),
        2 => GitExchangePlanV1::Receive(decode_receive(
            &mut bytes,
            preflight.format,
            exchange,
            protocol,
            principal,
            channel,
            expiry,
            input_limit,
            output_limit,
            trusted_validator,
        )?),
        _ => return Err(GitModelError::CorruptEncoding),
    };
    if !bytes.is_empty() {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(plan)
}

fn encode_protocol(bytes: &mut Vec<u8>, value: &GitProtocolV2ProfileV1) {
    bytes.push(value.service() as u8);
    bytes.push(value.format() as u8);
    push_u16(bytes, value.capabilities().len());
    for capability in value.capabilities() {
        bytes.push(*capability as u8);
    }
    bytes.extend_from_slice(value.digest().digest().as_bytes());
}

fn decode_protocol(
    bytes: &mut &[u8],
    format: GitObjectFormatV1,
) -> Result<GitProtocolV2ProfileV1, GitModelError> {
    let service = decode_protocol_service(take::<1>(bytes)?[0])?;
    if decode_format(take::<1>(bytes)?[0])? != format {
        return Err(GitModelError::CorruptEncoding);
    }
    let count = usize::from(u16::from_be_bytes(take(bytes)?));
    if count > MAXIMUM_GIT_PROTOCOL_V2_CAPABILITIES {
        return Err(GitModelError::CorruptEncoding);
    }
    let mut capabilities = Vec::new();
    capabilities
        .try_reserve_exact(count)
        .map_err(|_| GitModelError::Allocation)?;
    for _ in 0..count {
        capabilities.push(decode_protocol_capability(take::<1>(bytes)?[0])?);
    }
    let stored =
        GitProtocolV2CapabilitiesDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let profile = GitProtocolV2ProfileV1::new(service, format, capabilities)
        .map_err(|_| GitModelError::CorruptEncoding)?;
    if profile.digest() != stored {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(profile)
}

fn encode_common(
    bytes: &mut Vec<u8>,
    kind: u8,
    format: GitObjectFormatV1,
    exchange: ResourceId,
    principal: PrincipalId,
    channel: GitChannelBindingDigestV1,
    expiry: u64,
    input: u64,
    output: u64,
) {
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(kind);
    bytes.push(format as u8);
    bytes.extend_from_slice(exchange.as_bytes());
    bytes.extend_from_slice(principal.as_bytes());
    bytes.extend_from_slice(channel.digest().as_bytes());
    bytes.extend_from_slice(&expiry.to_be_bytes());
    bytes.extend_from_slice(&input.to_be_bytes());
    bytes.extend_from_slice(&output.to_be_bytes());
}

pub(super) fn encode_export(bytes: &mut Vec<u8>, value: &GitExportGenerationV1) {
    bytes.extend_from_slice(value.export().as_bytes());
    bytes.extend_from_slice(&value.generation().get().to_be_bytes());
    bytes.extend_from_slice(value.generation_digest().digest().as_bytes());
    bytes.extend_from_slice(value.project().as_bytes());
    bytes.extend_from_slice(value.repository().as_bytes());
    bytes.extend_from_slice(&value.repository_revision().get().to_be_bytes());
    encode_descriptor(bytes, value.bare_export());
    encode_whole_database(bytes, value.database());
    encode_refs(bytes, value.refs());
    bytes.extend_from_slice(value.ref_map().digest().as_bytes());
}

pub(super) fn decode_export(
    bytes: &mut &[u8],
    format: GitObjectFormatV1,
    trusted_validator: &GitTrustedValidatorV1,
) -> Result<GitExportGenerationV1, GitModelError> {
    let export = ResourceId::from_bytes(take(bytes)?);
    let generation = Revision::new(u64::from_be_bytes(take(bytes)?));
    let stored_generation_digest =
        GitExportGenerationDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let project = ProjectId::from_bytes(take(bytes)?);
    let repository = ResourceId::from_bytes(take(bytes)?);
    let repository_revision = Revision::new(u64::from_be_bytes(take(bytes)?));
    let descriptor = decode_descriptor(bytes)?;
    let database = decode_whole_database(bytes, format, trusted_validator)?;
    let refs = decode_refs(bytes, format)?;
    let stored_ref_map = GitRefMapDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let result = GitExportGenerationV1::new(
        export,
        generation,
        project,
        repository,
        repository_revision,
        descriptor,
        refs,
        database,
    )
    .map_err(|_| GitModelError::CorruptEncoding)?;
    if result.ref_map() != stored_ref_map || result.generation_digest() != stored_generation_digest
    {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(result)
}

fn encode_receive(bytes: &mut Vec<u8>, value: &GitReceivePlanV1) {
    let repository = value.repository();
    bytes.extend_from_slice(repository.repository().as_bytes());
    bytes.extend_from_slice(repository.project().as_bytes());
    bytes.extend_from_slice(repository.sandbox().as_bytes());
    bytes.extend_from_slice(repository.workspace().as_bytes());
    bytes.extend_from_slice(&repository.revision().get().to_be_bytes());
    bytes.extend_from_slice(&value.successor_revision().get().to_be_bytes());
    let fence = value.fence();
    bytes.extend_from_slice(&fence.desired_generation().get().to_be_bytes());
    bytes.extend_from_slice(fence.incarnation().as_bytes());
    bytes.extend_from_slice(&fence.assignment_epoch().get().to_be_bytes());
    bytes.extend_from_slice(&fence.namespace_generation().get().to_be_bytes());
    encode_refs(bytes, value.current_refs());
    encode_transitions(bytes, value.transitions());
    bytes.extend_from_slice(value.pre_ref_map().digest().as_bytes());
    bytes.extend_from_slice(value.post_ref_map().digest().as_bytes());
    encode_whole_database(bytes, value.pre_database());
    encode_whole_database(bytes, value.post_database());
    encode_descriptor(bytes, value.quarantine());
    bytes.extend_from_slice(value.quarantine_digest().digest().as_bytes());
    bytes.extend_from_slice(value.validation_policy().digest().as_bytes());
    bytes.extend_from_slice(value.atomic_cas().digest().as_bytes());
}

#[allow(clippy::too_many_arguments)]
fn decode_receive(
    bytes: &mut &[u8],
    format: GitObjectFormatV1,
    exchange: ResourceId,
    protocol: GitProtocolV2ProfileV1,
    principal: PrincipalId,
    channel: GitChannelBindingDigestV1,
    expiry: u64,
    input_limit: u64,
    output_limit: u64,
    trusted_validator: &GitTrustedValidatorV1,
) -> Result<GitReceivePlanV1, GitModelError> {
    let repository = ResourceId::from_bytes(take(bytes)?);
    let project = ProjectId::from_bytes(take(bytes)?);
    let sandbox = SandboxId::from_bytes(take(bytes)?);
    let workspace = ResourceId::from_bytes(take(bytes)?);
    let current_revision = Revision::new(u64::from_be_bytes(take(bytes)?));
    let stored_successor = Revision::new(u64::from_be_bytes(take(bytes)?));
    let fence = GitReceiveFenceV1::new(
        DesiredGeneration::new(u64::from_be_bytes(take(bytes)?)),
        IncarnationId::from_bytes(take(bytes)?),
        AssignmentEpoch::new(u64::from_be_bytes(take(bytes)?)),
        NamespaceGeneration::new(u64::from_be_bytes(take(bytes)?)),
    )
    .map_err(|_| GitModelError::CorruptEncoding)?;
    let current_refs = decode_refs(bytes, format)?;
    let transitions = decode_transitions(bytes, format, trusted_validator)?;
    let stored_pre_refs = GitRefMapDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let stored_post_refs = GitRefMapDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let pre_database = decode_whole_database(bytes, format, trusted_validator)?;
    let post_database = decode_whole_database(bytes, format, trusted_validator)?;
    let quarantine = decode_descriptor(bytes)?;
    let quarantine_digest =
        GitQuarantineDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let validation =
        GitValidationPolicyDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let stored_cas = GitAtomicCasDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let repository = GitRepositoryV1::new(
        repository,
        project,
        sandbox,
        workspace,
        format,
        current_revision,
    )
    .map_err(|_| GitModelError::CorruptEncoding)?;
    let result = GitReceivePlanV1::new(
        exchange,
        repository,
        protocol,
        principal,
        channel,
        fence,
        expiry,
        input_limit,
        output_limit,
        current_refs,
        transitions,
        pre_database,
        post_database,
        quarantine,
        validation,
    )
    .map_err(|_| GitModelError::CorruptEncoding)?;
    if result.successor_revision() != stored_successor
        || result.pre_ref_map() != stored_pre_refs
        || result.post_ref_map() != stored_post_refs
        || result.quarantine_digest() != quarantine_digest
        || result.atomic_cas() != stored_cas
    {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(result)
}

fn encode_audience(bytes: &mut Vec<u8>, value: &GitReadAudienceV1) {
    bytes.push(cache_kind_code(value.disclosure().kind()));
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(value.disclosure().domain_id().as_bytes());
    bytes.extend_from_slice(value.authorization().digest().as_bytes());
}
fn decode_audience(bytes: &mut &[u8]) -> Result<GitReadAudienceV1, GitModelError> {
    let kind = decode_cache_kind(take::<1>(bytes)?[0])?;
    if take::<7>(bytes)? != [0; 7] {
        return Err(GitModelError::CorruptEncoding);
    }
    let domain = CacheDomainId::from_bytes(take(bytes)?);
    let authorization = GitAudienceDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    GitReadAudienceV1::new(CacheDomain::new(kind, domain), authorization)
        .map_err(|_| GitModelError::CorruptEncoding)
}

pub(super) fn encode_whole_database(bytes: &mut Vec<u8>, value: &GitWholeObjectDatabaseV1) {
    encode_audience(bytes, value.audience());
    encode_graph(bytes, value.graph());
    let physical = value.physical();
    bytes.extend_from_slice(&physical.loose_object_count().to_be_bytes());
    bytes.extend_from_slice(&physical.pack_count().to_be_bytes());
    bytes.extend_from_slice(physical.pack_indexes().digest().as_bytes());
    bytes.extend_from_slice(physical.inventory().digest().as_bytes());
    encode_descriptor(bytes, value.validator().report());
    bytes.extend_from_slice(value.validator().policy().digest().as_bytes());
    bytes.extend_from_slice(value.validator().trust().digest().as_bytes());
}

pub(super) fn decode_whole_database(
    bytes: &mut &[u8],
    format: GitObjectFormatV1,
    trusted_validator: &GitTrustedValidatorV1,
) -> Result<GitWholeObjectDatabaseV1, GitModelError> {
    let audience = decode_audience(bytes)?;
    let graph = decode_graph(bytes, format, trusted_validator)?;
    let loose_objects = u64::from_be_bytes(take(bytes)?);
    let packs = u64::from_be_bytes(take(bytes)?);
    let pack_indexes =
        GitPackIndexSetDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let inventory =
        GitObjectInventoryDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let validator_report = decode_descriptor(bytes)?;
    let validator_policy =
        GitValidationPolicyDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let validator_trust =
        GitValidatorTrustDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let physical =
        GitPhysicalObjectEnumerationV1::new(&graph, loose_objects, packs, pack_indexes, inventory)
            .map_err(|_| GitModelError::CorruptEncoding)?;
    if validator_trust != trusted_validator.attestation() {
        return Err(GitModelError::CorruptEncoding);
    }
    let validator = GitGraphValidatorEvidenceV1::from_trusted(
        validator_report,
        graph.graph_proof(),
        validator_policy,
        trusted_validator,
    )
    .map_err(|_| GitModelError::CorruptEncoding)?;
    GitWholeObjectDatabaseV1::new(graph, physical, validator, audience, trusted_validator)
        .map_err(|_| GitModelError::CorruptEncoding)
}

fn encode_graph(bytes: &mut Vec<u8>, value: &GitObjectGraphEvidenceV1) {
    bytes.push(value.completeness() as u8);
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(&value.object_count().to_be_bytes());
    bytes.extend_from_slice(&value.total_object_bytes().to_be_bytes());
    bytes.extend_from_slice(value.object_database().digest().as_bytes());
    bytes.extend_from_slice(value.graph_proof().digest().as_bytes());
    push_u32(bytes, value.roots().len());
    for root in value.roots() {
        encode_oid_slot(bytes, *root);
    }
}
fn decode_graph(
    bytes: &mut &[u8],
    format: GitObjectFormatV1,
    trusted_validator: &GitTrustedValidatorV1,
) -> Result<GitObjectGraphEvidenceV1, GitModelError> {
    let completeness = decode_completeness(take::<1>(bytes)?[0])?;
    if take::<7>(bytes)? != [0; 7] {
        return Err(GitModelError::CorruptEncoding);
    }
    let count = u64::from_be_bytes(take(bytes)?);
    let total = u64::from_be_bytes(take(bytes)?);
    let odb = GitObjectDatabaseDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let graph_proof = GitGraphProofDigestV1::from_stored(ObjectDigest::from_bytes(take(bytes)?))?;
    let root_count = read_count(bytes, MAXIMUM_GIT_GRAPH_ROOTS)?;
    let mut roots = Vec::new();
    roots
        .try_reserve_exact(root_count)
        .map_err(|_| GitModelError::Allocation)?;
    for _ in 0..root_count {
        roots.push(decode_oid_slot(bytes, format)?);
    }
    trusted_validator
        .accept_object_graph(format, completeness, count, total, roots, odb, graph_proof)
        .map_err(|_| GitModelError::CorruptEncoding)
}

pub(super) fn encode_refs(bytes: &mut Vec<u8>, values: &[GitAdvertisedRefV1]) {
    push_u32(bytes, values.len());
    for value in values {
        push_u16(bytes, value.name().as_bytes().len());
        bytes.extend_from_slice(value.name().as_bytes());
        encode_oid_slot(bytes, value.object());
    }
}
pub(super) fn decode_refs(
    bytes: &mut &[u8],
    format: GitObjectFormatV1,
) -> Result<Vec<GitAdvertisedRefV1>, GitModelError> {
    let count = read_count(bytes, MAXIMUM_GIT_GRAPH_ROOTS)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| GitModelError::Allocation)?;
    for _ in 0..count {
        let length = usize::from(u16::from_be_bytes(take(bytes)?));
        let name = decode_ref_name(take_slice(bytes, length)?)?;
        let object = decode_oid_slot(bytes, format)?;
        values.push(GitAdvertisedRefV1::new(name, object));
    }
    git_ref_map_digest_v1(format, &values).map_err(|_| GitModelError::CorruptEncoding)?;
    Ok(values)
}

fn encode_transitions(bytes: &mut Vec<u8>, values: &[GitRefTransitionV1]) {
    push_u32(bytes, values.len());
    for value in values {
        push_u16(bytes, value.name().as_bytes().len());
        bytes.extend_from_slice(value.name().as_bytes());
        encode_optional_oid(bytes, value.expected());
        encode_optional_oid(bytes, value.proposed());
        bytes.push(u8::from(value.ancestry().is_some()));
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(
            value
                .ancestry()
                .map_or(ObjectDigest::from_bytes([0; 32]), |report| {
                    report.report().digest()
                })
                .as_bytes(),
        );
        bytes.extend_from_slice(
            value
                .ancestry()
                .map_or(ObjectDigest::from_bytes([0; 32]), |report| {
                    report.object_database().digest()
                })
                .as_bytes(),
        );
        bytes.extend_from_slice(
            value
                .ancestry()
                .map_or(ObjectDigest::from_bytes([0; 32]), |report| {
                    report.trust().digest()
                })
                .as_bytes(),
        );
    }
}
fn decode_transitions(
    bytes: &mut &[u8],
    format: GitObjectFormatV1,
    trusted_validator: &GitTrustedValidatorV1,
) -> Result<Vec<GitRefTransitionV1>, GitModelError> {
    let count = read_count(bytes, MAXIMUM_GIT_REF_TRANSITIONS)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| GitModelError::Allocation)?;
    for _ in 0..count {
        let length = usize::from(u16::from_be_bytes(take(bytes)?));
        let name = decode_ref_name(take_slice(bytes, length)?)?;
        let expected = decode_optional_oid(bytes, format)?;
        let proposed = decode_optional_oid(bytes, format)?;
        let ancestry_present = take::<1>(bytes)?[0];
        if ancestry_present > 1 || take::<7>(bytes)? != [0; 7] {
            return Err(GitModelError::CorruptEncoding);
        }
        let ancestry_digest = ObjectDigest::from_bytes(take(bytes)?);
        let ancestry_database = ObjectDigest::from_bytes(take(bytes)?);
        let ancestry_trust = ObjectDigest::from_bytes(take(bytes)?);
        let ancestry = match ancestry_present {
            0 if [ancestry_digest, ancestry_database, ancestry_trust]
                .iter()
                .all(|digest| digest.as_bytes() == &[0; 32]) =>
            {
                None
            }
            1 => {
                let old = expected.ok_or(GitModelError::CorruptEncoding)?;
                let new = proposed.ok_or(GitModelError::CorruptEncoding)?;
                Some(GitAncestryReportV1::from_stored(
                    trusted_validator,
                    name.clone(),
                    old,
                    new,
                    GitObjectDatabaseDigestV1::from_stored(ancestry_database)?,
                    ancestry_digest,
                    GitValidatorTrustDigestV1::from_stored(ancestry_trust)?,
                )?)
            }
            _ => return Err(GitModelError::CorruptEncoding),
        };
        values.push(
            GitRefTransitionV1::new(name, expected, proposed, ancestry)
                .map_err(|_| GitModelError::CorruptEncoding)?,
        );
    }
    Ok(values)
}

pub(super) fn encode_descriptor(bytes: &mut Vec<u8>, value: &GitDescriptorV1) {
    bytes.push(value.role() as u8);
    bytes.push(0);
    push_u16(bytes, value.descriptor().media_type().as_str().len());
    bytes.extend_from_slice(value.descriptor().media_type().as_str().as_bytes());
    bytes.extend_from_slice(value.descriptor().digest().as_bytes());
    bytes.extend_from_slice(&value.descriptor().encoded_size().to_be_bytes());
}
pub(super) fn decode_descriptor(bytes: &mut &[u8]) -> Result<GitDescriptorV1, GitModelError> {
    let role = decode_descriptor_role(take::<1>(bytes)?[0])?;
    if take::<1>(bytes)? != [0] {
        return Err(GitModelError::CorruptEncoding);
    }
    let length = usize::from(u16::from_be_bytes(take(bytes)?));
    let media = decode_string(take_slice(bytes, length)?)?;
    let media = MediaType::new(media).map_err(|_| GitModelError::CorruptEncoding)?;
    let descriptor = ObjectDescriptor::new(
        media,
        ObjectDigest::from_bytes(take(bytes)?),
        u64::from_be_bytes(take(bytes)?),
    );
    GitDescriptorV1::new(role, descriptor).map_err(|_| GitModelError::CorruptEncoding)
}

fn encode_oid_slot(bytes: &mut Vec<u8>, value: GitObjectIdV1) {
    let mut slot = [0_u8; 32];
    slot[..value.as_bytes().len()].copy_from_slice(value.as_bytes());
    bytes.extend_from_slice(&slot);
}
fn decode_oid_slot(
    bytes: &mut &[u8],
    format: GitObjectFormatV1,
) -> Result<GitObjectIdV1, GitModelError> {
    let slot = take::<32>(bytes)?;
    match format {
        GitObjectFormatV1::Sha1 if slot[20..] == [0; 12] => {
            GitObjectIdV1::from_bytes(format, &slot[..20])
        }
        GitObjectFormatV1::Sha256 => GitObjectIdV1::from_bytes(format, &slot),
        _ => Err(GitModelError::CorruptEncoding),
    }
    .map_err(|_| GitModelError::CorruptEncoding)
}
fn encode_optional_oid(bytes: &mut Vec<u8>, value: Option<GitObjectIdV1>) {
    bytes.push(u8::from(value.is_some()));
    match value {
        Some(value) => encode_oid_slot(bytes, value),
        None => bytes.extend_from_slice(&[0; 32]),
    }
}
fn decode_optional_oid(
    bytes: &mut &[u8],
    format: GitObjectFormatV1,
) -> Result<Option<GitObjectIdV1>, GitModelError> {
    let present = take::<1>(bytes)?[0];
    if present == 0 {
        if take::<32>(bytes)? == [0; 32] {
            Ok(None)
        } else {
            Err(GitModelError::CorruptEncoding)
        }
    } else if present == 1 {
        decode_oid_slot(bytes, format).map(Some)
    } else {
        Err(GitModelError::CorruptEncoding)
    }
}

fn preflight(encoded: &[u8]) -> Result<Preflight, GitModelError> {
    if encoded.len() < COMMON_BYTES + DIGEST_BYTES
        || encoded.len() > MAXIMUM_GIT_CONTROL_RECORD_BYTES
    {
        return Err(GitModelError::CorruptEncoding);
    }
    let mut bytes = &encoded[..encoded.len() - DIGEST_BYTES];
    if take::<8>(&mut bytes)? != *MAGIC || u16::from_be_bytes(take(&mut bytes)?) != VERSION {
        return Err(GitModelError::CorruptEncoding);
    }
    let kind = take::<1>(&mut bytes)?[0];
    let format = decode_format(take::<1>(&mut bytes)?[0])?;
    take_slice(&mut bytes, COMMON_BYTES - 12)?;
    preflight_protocol(&mut bytes)?;
    match kind {
        1 => {
            take_slice(&mut bytes, 96)?;
            preflight_descriptor(&mut bytes)?;
            take_slice(&mut bytes, AUDIENCE_BYTES)?;
            preflight_graph(&mut bytes)?;
            take_slice(&mut bytes, PHYSICAL_ENUMERATION_BYTES)?;
            preflight_descriptor(&mut bytes)?;
            take_slice(&mut bytes, 64)?;
            preflight_refs(&mut bytes)?;
            take_slice(&mut bytes, 32)?;
        }
        2 => {
            take_slice(&mut bytes, RECEIVE_FIXED_BEFORE_REFS)?;
            preflight_refs(&mut bytes)?;
            preflight_transitions(&mut bytes)?;
            take_slice(&mut bytes, 64)?;
            preflight_whole_database(&mut bytes)?;
            preflight_whole_database(&mut bytes)?;
            preflight_descriptor(&mut bytes)?;
            take_slice(&mut bytes, 96)?;
        }
        _ => return Err(GitModelError::CorruptEncoding),
    }
    if !bytes.is_empty() {
        return Err(GitModelError::CorruptEncoding);
    }
    Ok(Preflight { kind, format })
}

fn preflight_protocol(bytes: &mut &[u8]) -> Result<(), GitModelError> {
    take_slice(bytes, 2)?;
    let count = usize::from(u16::from_be_bytes(take(bytes)?));
    if count > MAXIMUM_GIT_PROTOCOL_V2_CAPABILITIES {
        return Err(GitModelError::CorruptEncoding);
    }
    take_slice(
        bytes,
        count
            .checked_add(32)
            .ok_or(GitModelError::CorruptEncoding)?,
    )?;
    Ok(())
}

fn preflight_graph(bytes: &mut &[u8]) -> Result<(), GitModelError> {
    take_slice(bytes, GRAPH_FIXED_BYTES - 4)?;
    let count = read_count(bytes, MAXIMUM_GIT_GRAPH_ROOTS)?;
    take_slice(
        bytes,
        count
            .checked_mul(32)
            .ok_or(GitModelError::CorruptEncoding)?,
    )?;
    Ok(())
}
fn preflight_refs(bytes: &mut &[u8]) -> Result<(), GitModelError> {
    let count = read_count(bytes, MAXIMUM_GIT_GRAPH_ROOTS)?;
    for _ in 0..count {
        let length = usize::from(u16::from_be_bytes(take(bytes)?));
        if length == 0 || length > MAXIMUM_GIT_REF_BYTES {
            return Err(GitModelError::CorruptEncoding);
        }
        take_slice(
            bytes,
            length
                .checked_add(32)
                .ok_or(GitModelError::CorruptEncoding)?,
        )?;
    }
    Ok(())
}

pub(super) fn preflight_export(bytes: &mut &[u8]) -> Result<(), GitModelError> {
    take_slice(bytes, 96)?;
    preflight_descriptor(bytes)?;
    preflight_whole_database(bytes)?;
    preflight_refs(bytes)?;
    take_slice(bytes, 32)?;
    Ok(())
}
fn preflight_transitions(bytes: &mut &[u8]) -> Result<(), GitModelError> {
    let count = read_count(bytes, MAXIMUM_GIT_REF_TRANSITIONS)?;
    if count == 0 {
        return Err(GitModelError::CorruptEncoding);
    }
    for _ in 0..count {
        let length = usize::from(u16::from_be_bytes(take(bytes)?));
        if length == 0 || length > MAXIMUM_GIT_REF_BYTES {
            return Err(GitModelError::CorruptEncoding);
        }
        take_slice(
            bytes,
            length
                .checked_add(170)
                .ok_or(GitModelError::CorruptEncoding)?,
        )?;
    }
    Ok(())
}
pub(super) fn preflight_descriptor(bytes: &mut &[u8]) -> Result<(), GitModelError> {
    take_slice(bytes, 2)?;
    let length = usize::from(u16::from_be_bytes(take(bytes)?));
    if length == 0 || length > 255 {
        return Err(GitModelError::CorruptEncoding);
    }
    take_slice(
        bytes,
        length
            .checked_add(40)
            .ok_or(GitModelError::CorruptEncoding)?,
    )?;
    Ok(())
}

pub(super) fn preflight_whole_database(bytes: &mut &[u8]) -> Result<(), GitModelError> {
    take_slice(bytes, AUDIENCE_BYTES)?;
    preflight_graph(bytes)?;
    take_slice(bytes, PHYSICAL_ENUMERATION_BYTES)?;
    preflight_descriptor(bytes)?;
    take_slice(bytes, 64)?;
    Ok(())
}

fn decode_ref_name(bytes: &[u8]) -> Result<GitRefNameV1, GitModelError> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(bytes.len())
        .map_err(|_| GitModelError::Allocation)?;
    value.extend_from_slice(bytes);
    GitRefNameV1::new(value).map_err(|_| GitModelError::CorruptEncoding)
}
fn decode_string(bytes: &[u8]) -> Result<String, GitModelError> {
    let text = std::str::from_utf8(bytes).map_err(|_| GitModelError::CorruptEncoding)?;
    let mut value = String::new();
    value
        .try_reserve_exact(text.len())
        .map_err(|_| GitModelError::Allocation)?;
    value.push_str(text);
    Ok(value)
}
fn push_u16(bytes: &mut Vec<u8>, value: usize) {
    let encoded = value.to_be_bytes();
    bytes.extend_from_slice(&encoded[encoded.len() - 2..]);
}
fn push_u32(bytes: &mut Vec<u8>, value: usize) {
    let encoded = value.to_be_bytes();
    bytes.extend_from_slice(&encoded[encoded.len() - 4..]);
}
fn read_count(bytes: &mut &[u8], maximum: usize) -> Result<usize, GitModelError> {
    let value = usize::try_from(u32::from_be_bytes(take(bytes)?))
        .map_err(|_| GitModelError::CorruptEncoding)?;
    if value > maximum {
        Err(GitModelError::CorruptEncoding)
    } else {
        Ok(value)
    }
}
fn decode_format(value: u8) -> Result<GitObjectFormatV1, GitModelError> {
    match value {
        1 => Ok(GitObjectFormatV1::Sha1),
        2 => Ok(GitObjectFormatV1::Sha256),
        _ => Err(GitModelError::CorruptEncoding),
    }
}
fn decode_completeness(value: u8) -> Result<GitGraphCompletenessV1, GitModelError> {
    match value {
        1 => Ok(GitGraphCompletenessV1::AdvertisedClosure),
        2 => Ok(GitGraphCompletenessV1::ValidatedQuarantineClosure),
        _ => Err(GitModelError::CorruptEncoding),
    }
}
fn decode_descriptor_role(value: u8) -> Result<GitDescriptorRoleV1, GitModelError> {
    match value {
        1 => Ok(GitDescriptorRoleV1::BareExport),
        2 => Ok(GitDescriptorRoleV1::ReceiveQuarantine),
        3 => Ok(GitDescriptorRoleV1::Pack),
        4 => Ok(GitDescriptorRoleV1::PackIndex),
        5 => Ok(GitDescriptorRoleV1::MultiPackIndex),
        6 => Ok(GitDescriptorRoleV1::GraphValidationReport),
        _ => Err(GitModelError::CorruptEncoding),
    }
}
fn decode_cache_kind(value: u8) -> Result<CacheDomainKind, GitModelError> {
    match value {
        1 => Ok(CacheDomainKind::Private),
        2 => Ok(CacheDomainKind::Project),
        3 => Ok(CacheDomainKind::TrustDomain),
        4 => Ok(CacheDomainKind::Public),
        _ => Err(GitModelError::CorruptEncoding),
    }
}
fn decode_protocol_service(value: u8) -> Result<GitProtocolV2ServiceV1, GitModelError> {
    match value {
        1 => Ok(GitProtocolV2ServiceV1::UploadPack),
        2 => Ok(GitProtocolV2ServiceV1::ReceivePack),
        _ => Err(GitModelError::CorruptEncoding),
    }
}
fn decode_protocol_capability(value: u8) -> Result<GitProtocolV2CapabilityV1, GitModelError> {
    match value {
        1 => Ok(GitProtocolV2CapabilityV1::Agent),
        2 => Ok(GitProtocolV2CapabilityV1::ObjectFormat),
        3 => Ok(GitProtocolV2CapabilityV1::SessionId),
        4 => Ok(GitProtocolV2CapabilityV1::LsRefs),
        5 => Ok(GitProtocolV2CapabilityV1::Fetch),
        6 => Ok(GitProtocolV2CapabilityV1::ServerOption),
        7 => Ok(GitProtocolV2CapabilityV1::ReportStatusV2),
        8 => Ok(GitProtocolV2CapabilityV1::DeleteRefs),
        9 => Ok(GitProtocolV2CapabilityV1::Atomic),
        10 => Ok(GitProtocolV2CapabilityV1::PushOptions),
        11 => Ok(GitProtocolV2CapabilityV1::SideBand64k),
        _ => Err(GitModelError::CorruptEncoding),
    }
}
fn take_slice<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], GitModelError> {
    let (value, remaining) = bytes
        .split_at_checked(length)
        .ok_or(GitModelError::CorruptEncoding)?;
    *bytes = remaining;
    Ok(value)
}
fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], GitModelError> {
    take_slice(bytes, N)?
        .try_into()
        .map_err(|_| GitModelError::CorruptEncoding)
}

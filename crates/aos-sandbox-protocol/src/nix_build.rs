//! Bounded nonauthorizing schemas for the fixed-domain Nix build protocol.
//!
//! Recipe signatures attest an independently admitted recipe, not a Controller
//! operation or physical readback. Store objects retain separate portable and
//! NAR identities; hashing a NAR cannot establish a portable Tree descriptor.
//! Fixed production owners must join these decoded facts to original admission,
//! current ownership, required floor custody and actual backing before effects.
//!
//! ```text
//! AOSNRP02 | canonical-json-length:u32be | canonical JSON | Ed25519:64
//! NixBuildRequestV2 / NixBuildResponseV2: exact canonical protobuf
//! ```

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerMethod, NixBuildRequestV2, NixBuildResponseV2,
};
use aos_sandbox_core::{
    DescriptorRole, NodeId, ObjectDescriptor, ObjectDescriptorVerifier, ObjectDigest,
    PortableMediaType, ProjectId, ProtocolId, ResourceId, SandboxId, validate_descriptor_role,
};
use buffa::Message as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedAssignmentFence,
    ValidatedHeader, exact_nonzero, validate_fence, validate_request_header,
};

mod historical;
mod observation;
mod portable_graph;

#[cfg(test)]
mod tests;

pub use observation::{NixBuildObservationV2, decode_nix_build_observation_v2};
pub use historical::{
    HistoricalNixBuildRequestV2, decode_historical_nix_build_request_v2,
    decode_historical_nix_build_response_v2, decode_historical_nix_build_observation_v2,
};

/// Maximum complete application request body, before outer signed framing.
pub const NIX_REQUEST_MAXIMUM_BYTES_V2: usize = 262_144;
/// Maximum application response body, also constrained by exact signed framing.
pub const NIX_RESPONSE_MAXIMUM_BYTES_V2: usize = 4_194_304;
/// Maximum independently admitted selected outputs in the first fixed domain.
pub const NIX_MAXIMUM_OUTPUTS_V2: usize = 256;
/// Maximum input objects, references or portable reconstruction records.
pub const NIX_MAXIMUM_OBJECTS_V2: usize = 4_096;
/// Maximum separately streamed materialization size of one admitted object.
pub const NIX_MAXIMUM_OBJECT_BYTES_V2: u64 = 1_073_741_824;

const RECIPE_MAGIC: &[u8; 8] = b"AOSNRP02";
const RECIPE_HEADER_BYTES: usize = 12;
const RECIPE_SIGNATURE_BYTES: usize = 64;
const RECIPE_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.nix.preadmitted-recipe.v2\0";
const RECIPE_IDENTITY_DOMAIN: &[u8] = b"aos.sandbox.nix.preadmitted-recipe-artifact.v2\0";

/// Retains one canonical portable reconstruction object, not store authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NixPortableObjectV2 {
    /// Exact Tree or Directory descriptor of the canonical encoded bytes.
    pub descriptor: ObjectDescriptor,
    /// Canonical portable CBOR used to reconstruct the actual store hierarchy.
    pub bytes: Vec<u8>,
}

/// Describes expected backing independently of its future physical observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NixStoreObjectV2 {
    /// Exact admitted `/nix/store` object identity, never a command argument grant.
    pub path: String,
    /// Portable raw Content or reconstructed Tree identity.
    pub portable: ObjectDescriptor,
    /// SHA256 of the separate canonical NAR byte stream.
    pub nar_sha256: ObjectDigest,
    /// Exact length of the separate canonical NAR byte stream.
    pub nar_size: u64,
    /// Complete, strictly path-ordered references observed from the private store.
    pub references: Vec<String>,
    /// Canonical Tree/Directory records; raw file content is streamed from backing.
    pub portable_objects: Vec<NixPortableObjectV2>,
}

/// Binds one selected derivation output name to its predicted known store object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NixExpectedOutputV2 {
    /// Exact selected derivation output name.
    pub name: String,
    /// Predicted identity and expected content, not evidence that it exists.
    pub object: NixStoreObjectV2,
}

/// Stores a bounded independently signed preadmitted recipe.
///
/// There is deliberately no operation ID: the genuine Controller admission
/// chooses and durably reserves that identity under its own capability/policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NixPreadmittedRecipeV2 {
    /// Selects the sole closed recipe schema, exactly two.
    pub version: u16,
    /// Independently authorized node.
    pub node: NodeId,
    /// Exact independently provisioned deployment commitment.
    pub deployment: ObjectDigest,
    /// Fixed logical narrowing endpoint.
    pub endpoint: ResourceId,
    /// Fixed physically isolated store domain.
    pub domain: ResourceId,
    /// Commitment of the complete domain binding.
    pub domain_commitment: ObjectDigest,
    /// Exact disclosure policy for this recipe and its path map.
    pub disclosure: ObjectDigest,
    /// Project whose current Controller policy independently admits this work.
    pub project: ProjectId,
    /// Existing sandbox selected by authenticated Start admission.
    pub sandbox: SandboxId,
    /// Exact portable SandboxSpecification descriptor from its assignment.
    pub specification: ObjectDescriptor,
    /// Exact portable Environment descriptor selected by that specification.
    pub environment: ObjectDescriptor,
    /// Canonical environment-generation manifest, verified by the Core reducer.
    pub generation_manifest: Vec<u8>,
    /// Exact effective policy; a recipe signature does not make it current.
    pub policy: ObjectDescriptor,
    /// Complete portable project source Tree.
    pub source: ObjectDescriptor,
    /// Exact lock-file raw Content descriptor.
    pub lock: ObjectDescriptor,
    /// Exact source object in the observed recipe input closure.
    pub source_path: String,
    /// Exact lock-file object in the observed recipe input closure.
    pub lock_path: String,
    /// Exact selected output attribute from the immutable manifest.
    pub selected_output: String,
    /// Exact target system from the immutable manifest.
    pub target_system: String,
    /// Owner-admitted derivation object; it is not selected by request DTOs.
    pub derivation: NixStoreObjectV2,
    /// Exact canonical derivation file contents, distinct from its NAR.
    pub derivation_bytes: Vec<u8>,
    /// Complete observed input closure, strictly ordered by path.
    pub inputs: Vec<NixStoreObjectV2>,
    /// Predicted known outputs, strictly ordered by output name.
    pub outputs: Vec<NixExpectedOutputV2>,
}

/// Reports a malformed or unauthentic bounded recipe or readback carrier.
#[derive(Debug, thiserror::Error)]
pub enum NixBuildSchemaErrorV2 {
    /// A closed field, ordering rule or aggregate bound is invalid.
    #[error("invalid fixed-domain Nix schema")]
    Invalid,
    /// Canonical JSON could not be decoded or reproduced.
    #[error("noncanonical fixed-domain Nix JSON")]
    Json(#[source] serde_json::Error),
    /// The independent purpose-separated recipe signature is invalid.
    #[error("independent Nix recipe signature is invalid")]
    Signature,
}

impl NixPreadmittedRecipeV2 {
    /// Validates pure recipe shape without producing execution authority.
    ///
    /// # Errors
    /// Rejects sentinels, invalid descriptor roles, path/options injection,
    /// unsupported unknown outputs, unordered maps and aggregate bounds.
    pub fn validate(&self) -> Result<(), NixBuildSchemaErrorV2> {
        if self.version != 2
            || self.node.as_bytes() == &[0; 16]
            || self.endpoint.as_bytes() == &[0; 16]
            || self.domain.as_bytes() == &[0; 16]
            || self.project.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || [self.deployment, self.domain_commitment, self.disclosure]
                .iter().any(|digest| digest.as_bytes() == &[0; 32])
            || validate_descriptor_role(DescriptorRole::SnapshotSpec, &self.specification).is_err()
            || self.environment.media_type().as_str() != PortableMediaType::Environment.as_str()
            || self.policy.media_type().as_str() != PortableMediaType::Policy.as_str()
            || self.source.media_type().as_str() != PortableMediaType::Tree.as_str()
            || self.lock.media_type().as_str() != PortableMediaType::Content.as_str()
            || [&self.specification, &self.environment, &self.policy, &self.source, &self.lock]
                .iter().any(|descriptor| descriptor.encoded_size() == 0
                    || descriptor.digest().as_bytes() == &[0; 32])
            || self.generation_manifest.is_empty()
            || self.generation_manifest.len() > 65_536
            || self.selected_output.is_empty()
            || self.selected_output.len() > 4_096
            || !self.selected_output.split('.').all(valid_output_name)
            || self.target_system.is_empty()
            || self.target_system.len() > 255
            || !self.target_system.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
            })
            || !self.derivation.path.ends_with(".drv")
            || self.derivation_bytes.is_empty()
            || self.derivation_bytes.len() > 131_072
            || self.derivation.portable.media_type().as_str() != PortableMediaType::Content.as_str()
            || self.derivation.portable.encoded_size() != self.derivation_bytes.len() as u64
            || self.inputs.is_empty()
            || self.inputs.len() > NIX_MAXIMUM_OBJECTS_V2
            || self.outputs.is_empty()
            || self.outputs.len() > NIX_MAXIMUM_OUTPUTS_V2
            || !self.inputs.windows(2).all(|pair| pair[0].path < pair[1].path)
            || !self.outputs.windows(2).all(|pair| pair[0].name < pair[1].name)
        {
            return Err(NixBuildSchemaErrorV2::Invalid);
        }

        verify_portable_object_bytes(&self.derivation.portable, &self.derivation_bytes)?;
        self.derivation.validate()?;
        let mut reconstruction_records = self.derivation.portable_objects.len();
        for input in &self.inputs {
            input.validate()?;
            reconstruction_records = reconstruction_records.checked_add(input.portable_objects.len())
                .ok_or(NixBuildSchemaErrorV2::Invalid)?;
            if input.references.iter().any(|reference| {
                !self.inputs.iter().any(|member| member.path == *reference)
            }) {
                return Err(NixBuildSchemaErrorV2::Invalid);
            }
        }
        if self.derivation.references.iter().any(|reference| {
            !self.inputs.iter().any(|member| member.path == *reference)
        }) {
            return Err(NixBuildSchemaErrorV2::Invalid);
        }
        for output in &self.outputs {
            if !valid_output_name(&output.name) {
                return Err(NixBuildSchemaErrorV2::Invalid);
            }
            output.object.validate()?;
            reconstruction_records = reconstruction_records.checked_add(output.object.portable_objects.len())
                .ok_or(NixBuildSchemaErrorV2::Invalid)?;
            if self.inputs.iter().any(|input| input.path == output.object.path)
                || self.outputs.iter().filter(|other| other.object.path == output.object.path).count() != 1
            {
                return Err(NixBuildSchemaErrorV2::Invalid);
            }
            if output.object.references.iter().any(|reference| {
                !self.inputs.iter().any(|member| member.path == *reference)
                    && !self.outputs.iter().any(|member| member.object.path == *reference)
                    && self.derivation.path != *reference
            }) {
                return Err(NixBuildSchemaErrorV2::Invalid);
            }
        }
        if reconstruction_records > NIX_MAXIMUM_OBJECTS_V2
            || !self.inputs.iter().any(|input| input.path == self.source_path && input.portable == self.source)
            || !self.inputs.iter().any(|input| input.path == self.lock_path && input.portable == self.lock)
        {
            return Err(NixBuildSchemaErrorV2::Invalid);
        }
        Ok(())
    }
}

impl NixStoreObjectV2 {
    /// Validates expected object shape, not physical backing or a GC-root lease.
    ///
    /// # Errors
    /// Rejects invalid paths, nonportable descriptors, unordered references,
    /// aliased reconstruction records and independently bounded material sizes.
    pub fn validate(&self) -> Result<(), NixBuildSchemaErrorV2> {
        if !valid_store_path(&self.path)
            || self.portable.digest().as_bytes() == &[0; 32]
            || self.portable.encoded_size() == 0
            || !matches!(self.portable.media_type().as_str(), value
                if value == PortableMediaType::Content.as_str() || value == PortableMediaType::Tree.as_str())
            || self.nar_sha256.as_bytes() == &[0; 32]
            || self.nar_size == 0
            || self.nar_size > NIX_MAXIMUM_OBJECT_BYTES_V2
            || self.references.len() > NIX_MAXIMUM_OBJECTS_V2
            || !self.references.windows(2).all(|pair| pair[0] < pair[1])
            || self.references.iter().any(|path| !valid_store_path(path))
            || self.portable_objects.len() > NIX_MAXIMUM_OBJECTS_V2
            || !self.portable_objects.windows(2).all(|pair| pair[0].descriptor < pair[1].descriptor)
        {
            return Err(NixBuildSchemaErrorV2::Invalid);
        }
        for object in &self.portable_objects {
            if object.bytes.is_empty()
                || object.bytes.len() > NIX_REQUEST_MAXIMUM_BYTES_V2
                || object.descriptor.encoded_size() != object.bytes.len() as u64
                || !matches!(object.descriptor.media_type().as_str(), value
                    if value == PortableMediaType::Tree.as_str() || value == PortableMediaType::Directory.as_str())
            {
                return Err(NixBuildSchemaErrorV2::Invalid);
            }

            verify_portable_object_bytes(&object.descriptor, &object.bytes)?;
        }

        // The complete graph owns canonical decoding and rejects unused records.
        portable_graph::validate(self)?;
        Ok(())
    }
}

// Portable identity commits media type and stored size as well as payload bytes.
// Role/bounds checks and canonical graph decoding remain separate obligations.
fn verify_portable_object_bytes(
    descriptor: &ObjectDescriptor,
    bytes: &[u8],
) -> Result<(), NixBuildSchemaErrorV2> {
    let mut verifier = ObjectDescriptorVerifier::new(descriptor.clone());
    verifier.update(bytes).map_err(|_| NixBuildSchemaErrorV2::Invalid)?;
    verifier.finish().map_err(|_| NixBuildSchemaErrorV2::Invalid)
}

/// Retains signature-verified recipe bytes without granting Controller admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedNixRecipeArtifactV2 {
    recipe: NixPreadmittedRecipeV2,
    bytes: Vec<u8>,
    digest: ObjectDigest,
}

impl VerifiedNixRecipeArtifactV2 {
    /// Borrows the pure recipe whose independent signature verified.
    #[must_use]
    pub const fn recipe(&self) -> &NixPreadmittedRecipeV2 {
        &self.recipe
    }

    /// Borrows the exact original independent signed artifact.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the purpose-separated identity of the complete signed artifact.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

/// Verifies a bounded recipe with a separately supplied independent issuer pin.
///
/// This proves cryptographic authenticity only. Production owners must load
/// their pin from actual fixed named custody, not a request-provided key.
///
/// # Errors
/// Rejects malformed shape, noncanonical JSON, weak keys or invalid signatures.
pub fn verify_nix_recipe_artifact_v2(
    bytes: &[u8],
    independent_issuer: [u8; 32],
) -> Result<VerifiedNixRecipeArtifactV2, NixBuildSchemaErrorV2> {
    if bytes.len() < RECIPE_HEADER_BYTES + RECIPE_SIGNATURE_BYTES
        || bytes.len() > NIX_REQUEST_MAXIMUM_BYTES_V2
        || !bytes.starts_with(RECIPE_MAGIC)
    {
        return Err(NixBuildSchemaErrorV2::Invalid);
    }
    let length = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| NixBuildSchemaErrorV2::Invalid)?) as usize;
    let end = RECIPE_HEADER_BYTES.checked_add(length).ok_or(NixBuildSchemaErrorV2::Invalid)?;
    if end.checked_add(RECIPE_SIGNATURE_BYTES) != Some(bytes.len()) {
        return Err(NixBuildSchemaErrorV2::Invalid);
    }
    let recipe: NixPreadmittedRecipeV2 = serde_json::from_slice(&bytes[RECIPE_HEADER_BYTES..end])
        .map_err(NixBuildSchemaErrorV2::Json)?;
    recipe.validate()?;
    if serde_json::to_vec(&recipe).map_err(NixBuildSchemaErrorV2::Json)? != bytes[RECIPE_HEADER_BYTES..end] {
        return Err(NixBuildSchemaErrorV2::Invalid);
    }
    let key = VerifyingKey::from_bytes(&independent_issuer).map_err(|_| NixBuildSchemaErrorV2::Signature)?;
    if key.is_weak() {
        return Err(NixBuildSchemaErrorV2::Signature);
    }
    let signature = Signature::from_slice(&bytes[end..]).map_err(|_| NixBuildSchemaErrorV2::Signature)?;
    let mut message = Vec::with_capacity(RECIPE_SIGNATURE_DOMAIN.len() + end);
    message.extend_from_slice(RECIPE_SIGNATURE_DOMAIN);
    message.extend_from_slice(&bytes[..end]);
    key.verify_strict(&message, &signature).map_err(|_| NixBuildSchemaErrorV2::Signature)?;

    Ok(VerifiedNixRecipeArtifactV2 {
        recipe,
        bytes: bytes.to_vec(),
        digest: ObjectDigest::from_bytes(Sha256::new().chain_update(RECIPE_IDENTITY_DOMAIN).chain_update(bytes).finalize().into()),
    })
}

/// Retains canonical comparison coordinates after fixed audience/header checks.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedNixBuildRequestV2 {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    wire: NixBuildRequestV2,
    commitment: [u8; 32],
    method: BrokerMethod,
}

impl ValidatedNixBuildRequestV2 {
    /// Borrows the checked header, including the original deadline.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Borrows the exact structural assignment fence, not current ownership proof.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Borrows the comparison payload; it cannot grant path or effect authority.
    #[must_use]
    pub const fn wire(&self) -> &NixBuildRequestV2 {
        &self.wire
    }

    /// Returns the method-separated complete-body commitment.
    #[must_use]
    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Returns the exact original method included in the semantic commitment.
    #[must_use]
    pub const fn method(&self) -> BrokerMethod {
        self.method
    }
}

/// Decodes one exact descriptor-free fixed-domain method request.
///
/// # Errors
/// Rejects excess allocation, unknown fields, wrong purpose/audience, expired
/// deadlines and missing comparison coordinates before privileged work.
pub fn decode_nix_build_request_v2(
    bytes: &[u8],
    method: BrokerMethod,
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedNixBuildRequestV2, ProtocolValidationError> {
    require_nix_request_size(bytes)?;
    if policy.audience != Audience::AUDIENCE_NODE_CONTROLLER || !is_nix_method(method) {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    let wire = decode_nix_request_wire(bytes)?;
    let header = validate_request_header(
        wire.header.as_option().ok_or(ProtocolValidationError::MissingField("header"))?,
        peer, policy, ProtocolId::NixBuildBroker, now_boottime_nanoseconds,
    )?;
    let (fence, commitment) = compare_nix_request_body(bytes, method, &wire)?;

    Ok(ValidatedNixBuildRequestV2 {
        header,
        fence,
        wire,
        commitment,
        method,
    })
}

fn require_nix_request_size(bytes: &[u8]) -> Result<(), ProtocolValidationError> {
    if bytes.len() > NIX_REQUEST_MAXIMUM_BYTES_V2 {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    Ok(())
}

fn decode_nix_request_wire(bytes: &[u8]) -> Result<NixBuildRequestV2, ProtocolValidationError> {
    let wire = NixBuildRequestV2::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !wire.__buffa_unknown_fields.is_empty() || wire.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    Ok(wire)
}

// Both callers finish their distinct header checks before the same fence/body
// comparator. This helper does not admit a peer, deadline, recipe or operation.
fn compare_nix_request_body(
    bytes: &[u8],
    method: BrokerMethod,
    wire: &NixBuildRequestV2,
) -> Result<(ValidatedAssignmentFence, [u8; 32]), ProtocolValidationError> {
    let fence = validate_fence(wire.fence.as_option().ok_or(ProtocolValidationError::MissingField("fence"))?)?;
    exact_nonzero::<16>(&wire.operation_id, "operation_id")?;
    for (value, name) in [
        (&wire.recipe_digest, "recipe_digest"), (&wire.domain_digest, "domain_digest"),
        (&wire.disclosure_digest, "disclosure_digest"), (&wire.environment_digest, "environment_digest"),
        (&wire.parent_admission_digest, "parent_admission_digest"),
        (&wire.input_presentation_digest, "input_presentation_digest"),
        (&wire.expected_output_map_digest, "expected_output_map_digest"),
    ] { exact_nonzero::<32>(value, name)?; }
    if method == BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2 {
        if !wire.build_transaction_digest.is_empty() || !wire.original_realization_digest.is_empty() {
            return Err(ProtocolValidationError::InvalidField("resolve effect coordinates"));
        }
    } else {
        exact_nonzero::<32>(&wire.build_transaction_digest, "build_transaction_digest")?;
        if method == BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2 {
            exact_nonzero::<32>(&wire.original_realization_digest, "original_realization_digest")?;
        } else if !wire.original_realization_digest.is_empty() {
            return Err(ProtocolValidationError::InvalidField("realize original coordinate"));
        }
    }
    let commitment = Sha256::new().chain_update(b"aos.sandbox.nix.method-request.v2\0")
        .chain_update((method as i32).to_be_bytes()).chain_update((bytes.len() as u64).to_be_bytes())
        .chain_update(bytes).finalize().into();
    Ok((fence, commitment))
}

/// Decodes response shape and exact original-request comparisons.
///
/// # Errors
/// Rejects oversized or noncanonical responses and mismatched fixed identities.
/// Payload authenticity and actual content/readback remain owner responsibilities.
pub fn decode_nix_build_response_v2(
    bytes: &[u8],
    request: &ValidatedNixBuildRequestV2,
    method: BrokerMethod,
) -> Result<NixBuildResponseV2, ProtocolValidationError> {
    compare_nix_build_response_v2(bytes, &request.comparison(), method)
}

// One borrowed comparison view bridges live and historical DATA; neither
// constructing it nor using it performs admission or produces a live request.
#[derive(Clone, Copy)]
struct NixRequestComparisonV2<'request> {
    request_id: &'request [u8; 16],
    wire: &'request NixBuildRequestV2,
    commitment: [u8; 32],
    method: BrokerMethod,
}

impl NixRequestComparisonV2<'_> {
    const fn wire(&self) -> &NixBuildRequestV2 {
        self.wire
    }

    const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    const fn method(&self) -> BrokerMethod {
        self.method
    }
}

impl ValidatedNixBuildRequestV2 {
    fn comparison(&self) -> NixRequestComparisonV2<'_> {
        NixRequestComparisonV2 {
            request_id: self.header.request_id(),
            wire: &self.wire,
            commitment: self.commitment,
            method: self.method,
        }
    }
}

fn compare_nix_build_response_v2(
    bytes: &[u8],
    request: &NixRequestComparisonV2<'_>,
    method: BrokerMethod,
) -> Result<NixBuildResponseV2, ProtocolValidationError> {
    if bytes.len() > NIX_RESPONSE_MAXIMUM_BYTES_V2 {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    if method != request.method {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    let response = NixBuildResponseV2::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    if response.request_id.as_slice() != request.request_id
        || response.recipe_digest != request.wire.recipe_digest
        || response.domain_digest != request.wire.domain_digest
        || response.observation.is_empty()
        || if method == BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2 {
            response.recipe_admission.is_empty() || response.recipe_admission.len() > NIX_REQUEST_MAXIMUM_BYTES_V2
        } else { !response.recipe_admission.is_empty() }
    {
        return Err(ProtocolValidationError::InvalidField("Nix original response"));
    }
    observation::compare_nix_build_observation_v2(&response.observation, request)?;
    Ok(response)
}

fn valid_output_name(value: &str) -> bool {
    value.len() <= 255
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_store_path(path: &str) -> bool {
    let Some(name) = path.strip_prefix("/nix/store/") else {
        return false;
    };
    let Some((hash, package)) = name.split_once('-') else {
        return false;
    };
    name.len() <= 255 && hash.len() == 32
        && hash.bytes().all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        && !package.is_empty() && package.is_ascii()
        && package.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'='))
}

const fn is_nix_method(method: BrokerMethod) -> bool {
    matches!(method, BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2
        | BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2
        | BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2)
}

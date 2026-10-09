//! Defines comparison DATA for the selected Nix Start-to-Storage preparation.
//!
//! Neither a signed input family nor a decoded request establishes current
//! ownership, a physical store cut, Apply permission or a completed Start.
//! The Controller and Storage must join their original held owners separately.
//! The old recipe graph and Clone Prepare decoders remain the sole engines.
//!
//! ```text
//! origin: AOSNXG01 | canonical JSON
//! prefix: AOSNXS01 | fixed, big-endian original Start coordinates
//! family: AOSNXV02 | original-v1-length:u32 | exact original V1 artifact
//!         | data-length:u32 | canonical family JSON | signature:64
//! request: protobuf { canonical_prepare:1, original_start_prefix:2, generation_origin:3 }
//! ```

use aos_proto::aos::sandbox::local::v1::{
    PrepareNixStorageGenerationRequestV1, PrepareStorageCatalogRequest,
};
use aos_sandbox_core::bounded_codec::{BoundedReader, ReadError};
use aos_sandbox_core::{BrokerArgumentCommitment, ObjectDescriptor, PortableMediaType};
use buffa::Message as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::nix_build::VerifiedNixRecipeArtifactV2;
use crate::semantics::{CanonicalStoragePreparationSemanticsV1, StoragePreparationOperationV1};
use crate::{PeerCredentials, PeerPolicy, ProtocolValidationError};

/// Maximum complete selected method body, including all three fields.
pub const NIX_GENERATION_REQUEST_MAXIMUM_BYTES_V1: usize = 32_768;
/// Maximum independently provisioned selected input family.
pub const NIX_GENERATION_FAMILY_MAXIMUM_BYTES_V2: usize = 1_048_576;
/// Maximum canonical generation-origin comparison record.
pub const NIX_GENERATION_ORIGIN_MAXIMUM_BYTES_V1: usize = 4_096;
/// Maximum canonical original-Start comparison record.
pub const NIX_GENERATION_PREFIX_MAXIMUM_BYTES_V1: usize = 2_048;
/// Maximum complete added comparison context, including protobuf framing.
pub const NIX_GENERATION_CONTEXT_MAXIMUM_BYTES_V1: usize = 8_192;

const FAMILY_DOMAIN: &[u8] = b"aos.sandbox.nix.online-store.snapshot.v2\0";
const FAMILY_ARTIFACT_DOMAIN: &[u8] = b"aos.sandbox.nix.online-store.snapshot-artifact.v2\0";
const ORIGINAL_ARTIFACT_DOMAIN: &[u8] = b"aos.sandbox.nix.online-store.snapshot-artifact.v1\0";
const CONTROLS: [(&str, u64); 4] = [
    ("nix/var/nix/db/db.sqlite", 16_777_216),
    ("nix/var/nix/db/schema", 65_536),
    ("nix/var/nix/db/reserved", 0),
    ("etc/nix/nix.conf", 65_536),
];

/// Names independently signed predecessor coordinates for one new generation.
///
/// All fields are historical comparison DATA. Storage independently resolves
/// the snapshot, active hold, policy and complete metadata from its own writer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NixGenerationOriginV1 {
    /// Closed version, exactly one.
    pub version: u16,
    /// Independently configured node identity.
    pub node: [u8; 16],
    /// Exact deployment commitment.
    pub deployment: [u8; 32],
    /// Exact fixed input domain.
    pub domain: [u8; 16],
    /// Complete fixed-domain binding commitment.
    pub domain_commitment: [u8; 32],
    /// Original project identity.
    pub project: [u8; 16],
    /// Original sandbox identity.
    pub sandbox: [u8; 16],
    /// Original assignment incarnation.
    pub incarnation: [u8; 16],
    /// Predecessor generation; the selected successor is checked `G + 1`.
    pub source_generation: u64,
    /// Digest of the complete exact original signed V1 input artifact.
    pub input_artifact: [u8; 32],
    /// Complete original public source Tree descriptor.
    pub public_tree: ObjectDescriptor,
    /// Independently catalogued Storage workspace handle.
    pub storage_handle: [u8; 32],
    /// Independently catalogued immutable source version handle.
    pub source_version_handle: [u8; 32],
    /// Exact active snapshot hold to resolve locally.
    pub hold_id: [u8; 16],
    /// Expected locally derived root-policy digest.
    pub root_policy_digest: [u8; 32],
    /// Expected locally derived complete Clone identity commitment.
    pub clone_identity_digest: [u8; 32],
    /// Exact authenticated whole source-metadata record digest.
    pub metadata_digest: [u8; 32],
    /// Original authenticated inventory generation.
    pub inventory_generation: u64,
    /// Original authenticated complete inventory digest.
    pub inventory_digest: [u8; 32],
    /// Original catalog predecessor generation.
    pub catalog_generation: u64,
    /// Original catalog predecessor digest.
    pub catalog_digest: [u8; 32],
    /// Selected workspace quota compared to the actual resolver policy.
    pub quota_bytes: u64,
    /// Selected reservation compared to the actual resolver policy.
    pub reservation_bytes: u64,
    /// Complete independently signed original control comparison DATA.
    ///
    /// Fixed order is database, schema, reserved marker and configuration.
    /// These tuples do not attest current inodes or grant control-file writes.
    pub controls: [NixGenerationControlV1; 4],
}

impl NixGenerationOriginV1 {
    /// Encodes the sole canonical selected origin without admitting authority.
    ///
    /// # Errors
    /// Rejects sentinels, unsupported versions, descriptor roles or bounds.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolValidationError> {
        self.validate()?;
        let json = serde_json::to_vec(self).map_err(|_| invalid("generation origin JSON"))?;
        if json.len() > NIX_GENERATION_ORIGIN_MAXIMUM_BYTES_V1 - 8 {
            return Err(invalid("generation origin bound"));
        }
        let mut bytes = Vec::with_capacity(8 + json.len());
        bytes.extend_from_slice(b"AOSNXG01");
        bytes.extend_from_slice(&json);
        Ok(bytes)
    }

    /// Decodes exact canonical comparison bytes, never a Storage permit.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, unknown-field or inconsistent DATA.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() < 9 || bytes.len() > NIX_GENERATION_ORIGIN_MAXIMUM_BYTES_V1
            || bytes.get(..8) != Some(b"AOSNXG01")
        {
            return Err(invalid("generation origin framing"));
        }
        let value: Self = serde_json::from_slice(&bytes[8..])
            .map_err(|_| invalid("generation origin JSON"))?;
        if value.encode()?.as_slice() != bytes {
            return Err(invalid("generation origin canonical bytes"));
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.version != 1
            || [self.node, self.domain, self.project, self.sandbox, self.incarnation, self.hold_id]
                .iter().any(|value| *value == [0; 16] || *value == [0xff; 16])
            || [self.deployment, self.domain_commitment, self.input_artifact,
                self.storage_handle, self.source_version_handle, self.root_policy_digest,
                self.clone_identity_digest, self.metadata_digest, self.inventory_digest,
                self.catalog_digest].iter().any(|value| *value == [0; 32])
            || self.source_generation.checked_add(1).is_none()
            || self.inventory_generation == 0 || self.catalog_generation == 0
            || self.quota_bytes == 0 || self.reservation_bytes > self.quota_bytes
            || self.public_tree.media_type().as_str() != PortableMediaType::Tree.as_str()
            || self.public_tree.encoded_size() == 0
            || self.public_tree.digest().as_bytes() == &[0; 32]
        {
            return Err(invalid("generation origin fields"));
        }
        for (index, (control, (name, maximum))) in self.controls.iter().zip(CONTROLS).enumerate() {
            if control.name != name || control.bytes > maximum
                || usize::from(control.kind) != index + 1 || control.source_inode == 0
                || control.sha256 == [0; 32] || control.verity_sha256 == [0; 32]
            {
                return Err(invalid("generation origin complete controls"));
            }
        }
        Ok(())
    }
}

/// Commits the actual accepted Start and its original non-renewable clock cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NixGenerationStartPrefixV1 {
    /// Original accepted public Start operation.
    pub operation: [u8; 16],
    /// Original pending Effect step, exactly zero for this prefix.
    pub step: u32,
    /// Original assignment binding digest.
    pub assignment: [u8; 32],
    /// Complete original Desired bytes commitment.
    pub desired: [u8; 32],
    /// Complete original ordinary Effect bytes commitment.
    pub effect: [u8; 32],
    /// Exact independently signed retained recipe artifact digest.
    pub recipe: [u8; 32],
    /// Complete selected signed input/control-family artifact digest.
    pub input_set: [u8; 32],
    /// Original public resource-version/incarnation presentation commitment.
    pub presentation: [u8; 32],
    /// Exact fixed input domain.
    pub domain: [u8; 16],
    /// Exact original project.
    pub project: [u8; 16],
    /// Exact original sandbox.
    pub sandbox: [u8; 16],
    /// Exact original assignment incarnation.
    pub incarnation: [u8; 16],
    /// Complete canonical origin digest.
    pub origin: [u8; 32],
    /// Original independently provisioned source generation.
    pub source_generation: u64,
    /// Checked successor generation, exactly `source_generation + 1`.
    pub next_generation: u64,
    /// Original protected boot identity.
    pub host_boot_id: [u8; 16],
    /// Original assignment acquisition's paired wall observation.
    pub first_wall_seconds: i64,
    /// Original assignment acquisition's paired BOOTTIME observation.
    pub first_boottime_nanoseconds: u64,
    /// Original exclusive assignment deadline, never a new transport lease.
    pub deadline_boottime_nanoseconds: u64,
}

impl NixGenerationStartPrefixV1 {
    /// Encodes fixed-order original coordinates without issuing authority.
    ///
    /// # Errors
    /// Rejects invalid identities, commitments, generations or clock bounds.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolValidationError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(372);
        bytes.extend_from_slice(b"AOSNXS01");
        bytes.extend_from_slice(&self.operation);
        bytes.extend_from_slice(&self.step.to_be_bytes());
        for value in [self.assignment, self.desired, self.effect, self.recipe,
            self.input_set, self.presentation]
        {
            bytes.extend_from_slice(&value);
        }
        for value in [self.domain, self.project, self.sandbox, self.incarnation] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(&self.origin);
        bytes.extend_from_slice(&self.source_generation.to_be_bytes());
        bytes.extend_from_slice(&self.next_generation.to_be_bytes());
        bytes.extend_from_slice(&self.host_boot_id);
        bytes.extend_from_slice(&self.first_wall_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.first_boottime_nanoseconds.to_be_bytes());
        bytes.extend_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes the same fixed prefix, rejecting trailing or substituted DATA.
    ///
    /// # Errors
    /// Rejects wrong framing, invalid fields, truncation or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() > NIX_GENERATION_PREFIX_MAXIMUM_BYTES_V1 {
            return Err(invalid("generation prefix bound"));
        }
        let mut reader = BoundedReader::new(bytes, generation_read_error);
        if read_generation_fixed::<8>(&mut reader)? != *b"AOSNXS01" {
            return Err(invalid("generation prefix magic"));
        }
        let value = Self {
            operation: read_generation_fixed(&mut reader)?,
            step: u32::from_be_bytes(read_generation_fixed(&mut reader)?),
            assignment: read_generation_fixed(&mut reader)?,
            desired: read_generation_fixed(&mut reader)?,
            effect: read_generation_fixed(&mut reader)?,
            recipe: read_generation_fixed(&mut reader)?,
            input_set: read_generation_fixed(&mut reader)?,
            presentation: read_generation_fixed(&mut reader)?,
            domain: read_generation_fixed(&mut reader)?,
            project: read_generation_fixed(&mut reader)?,
            sandbox: read_generation_fixed(&mut reader)?,
            incarnation: read_generation_fixed(&mut reader)?,
            origin: read_generation_fixed(&mut reader)?,
            source_generation: u64::from_be_bytes(read_generation_fixed(&mut reader)?),
            next_generation: u64::from_be_bytes(read_generation_fixed(&mut reader)?),
            host_boot_id: read_generation_fixed(&mut reader)?,
            first_wall_seconds: i64::from_be_bytes(read_generation_fixed(&mut reader)?),
            first_boottime_nanoseconds: u64::from_be_bytes(read_generation_fixed(&mut reader)?),
            deadline_boottime_nanoseconds: u64::from_be_bytes(read_generation_fixed(&mut reader)?),
        };
        reader.finish()
            .map_err(|_| invalid("generation trailing bytes"))?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.step != 0
            || [self.operation, self.domain, self.project, self.sandbox,
                self.incarnation, self.host_boot_id].iter()
                .any(|value| *value == [0; 16] || *value == [0xff; 16])
            || [self.assignment, self.desired, self.effect, self.recipe, self.input_set,
                self.presentation, self.origin].iter().any(|value| *value == [0; 32])
            || self.source_generation.checked_add(1) != Some(self.next_generation)
            || self.first_boottime_nanoseconds >= self.deadline_boottime_nanoseconds
        {
            return Err(invalid("generation prefix coordinates"));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InputMemberV2 {
    path: String,
    descriptor: ObjectDescriptor,
}

/// Retains one exact fixed control member without claiming physical currentness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NixGenerationControlV1 {
    /// Closed kind, respectively one through four in fixed control order.
    pub kind: u8,
    /// Exact fixed basename, never a caller-selected path.
    pub name: String,
    /// Exact original control byte length.
    pub bytes: u64,
    /// Hash of all original control bytes, including an allowed empty marker.
    pub sha256: [u8; 32],
    /// Expected original source fs-verity digest.
    pub verity_sha256: [u8; 32],
    /// Expected original source inode, independently observed at physical use.
    pub source_inode: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FamilyDataV2 {
    version: u16,
    recipe_artifact: [u8; 32],
    inputs: Vec<InputMemberV2>,
    origin: NixGenerationOriginV1,
}

/// Retains authenticated comparison DATA from the selected independent family.
///
/// The original V1 artifact is opaque and exactly committed. This verifier
/// does not decode its semantic contents or create a current LocalStore cut.
pub struct VerifiedNixGenerationInputFamilyV2 {
    data: FamilyDataV2,
    artifact: [u8; 32],
}

impl VerifiedNixGenerationInputFamilyV2 {
    /// Verifies the selected purpose and exact retained recipe/input closure.
    ///
    /// # Errors
    /// Rejects malformed framing, weak/wrong issuer, noncanonical fields,
    /// incomplete inputs/controls or a substituted original artifact/recipe.
    pub fn decode(
        bytes: &[u8],
        issuer: [u8; 32],
        recipe: &VerifiedNixRecipeArtifactV2,
    ) -> Result<Self, ProtocolValidationError> {
        if bytes.len() < 85 || bytes.len() > NIX_GENERATION_FAMILY_MAXIMUM_BYTES_V2 {
            return Err(invalid("generation family bound"));
        }
        let signed_end = bytes.len() - 64;
        let mut reader = BoundedReader::new(&bytes[..signed_end], generation_read_error);
        if read_generation_fixed::<8>(&mut reader)? != *b"AOSNXV02" {
            return Err(invalid("generation family magic"));
        }
        let original = read_generation_variable(&mut reader, NIX_GENERATION_FAMILY_MAXIMUM_BYTES_V2)?;
        if original.len() < 77 || original.get(..8) != Some(b"AOSNXV01") {
            return Err(invalid("original input artifact framing"));
        }
        let original_body = u32::from_be_bytes(original[8..12].try_into()
            .map_err(|_| invalid("original input artifact length"))?) as usize;
        if original_body.checked_add(76) != Some(original.len()) {
            return Err(invalid("original input artifact length"));
        }
        let json = read_generation_variable(&mut reader, NIX_GENERATION_FAMILY_MAXIMUM_BYTES_V2)?;
        reader.finish()
            .map_err(|_| invalid("generation trailing bytes"))?;

        let key = VerifyingKey::from_bytes(&issuer)
            .map_err(|_| invalid("generation family issuer"))?;
        if key.is_weak() {
            return Err(invalid("generation family issuer"));
        }
        let mut preimage = Vec::with_capacity(FAMILY_DOMAIN.len() + signed_end);
        preimage.extend_from_slice(FAMILY_DOMAIN);
        preimage.extend_from_slice(&bytes[..signed_end]);
        let signature = Signature::from_slice(&bytes[signed_end..])
            .map_err(|_| invalid("generation family signature"))?;
        key.verify_strict(&preimage, &signature)
            .map_err(|_| invalid("generation family signature"))?;

        let data: FamilyDataV2 = serde_json::from_slice(json)
            .map_err(|_| invalid("generation family JSON"))?;
        if serde_json::to_vec(&data).map_err(|_| invalid("generation family JSON"))? != json {
            return Err(invalid("generation family canonical bytes"));
        }
        let origin = &data.origin;
        origin.validate()?;
        let expected = recipe.recipe();
        if data.version != 2 || data.recipe_artifact != *recipe.digest().as_bytes()
            || data.inputs.len() != expected.inputs.len().checked_add(1)
                .ok_or_else(|| invalid("generation family input count"))?
            || data.inputs.len() > 4_096
            || origin.node != *expected.node.as_bytes()
            || origin.deployment != *expected.deployment.as_bytes()
            || origin.domain != *expected.domain.as_bytes()
            || origin.domain_commitment != *expected.domain_commitment.as_bytes()
            || origin.project != *expected.project.as_bytes()
            || origin.sandbox != *expected.sandbox.as_bytes()
            || origin.public_tree != expected.source
            || origin.input_artifact != artifact_digest(ORIGINAL_ARTIFACT_DOMAIN, original)
        {
            return Err(invalid("generation family original bindings"));
        }
        for (member, expected) in data.inputs.iter().zip(
            std::iter::once(&expected.derivation).chain(&expected.inputs),
        ) {
            if member.path != expected.path || member.descriptor != expected.portable {
                return Err(invalid("generation family complete inputs"));
            }
        }
        Ok(Self { data, artifact: artifact_digest(FAMILY_ARTIFACT_DOMAIN, bytes) })
    }

    /// Borrows independently signed historical predecessor DATA.
    #[must_use]
    pub fn origin(&self) -> &NixGenerationOriginV1 {
        &self.data.origin
    }

    /// Returns the commitment of the complete exact signed selected family.
    #[must_use]
    pub const fn artifact_digest(&self) -> [u8; 32] {
        self.artifact
    }
}

/// Decodes the whole selected request with the existing nested Clone engine.
///
/// This is nonadmitting structural DATA; receiving authority verifies the
/// whole wrapper's argument commitment and all actual original owner cuts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalNixGenerationPreparationV1 {
    prepare: CanonicalStoragePreparationSemanticsV1,
    prefix: NixGenerationStartPrefixV1,
    origin: NixGenerationOriginV1,
    commitment: BrokerArgumentCommitment,
}

impl CanonicalNixGenerationPreparationV1 {
    /// Checks canonical whole-wrapper bytes and every duplicated coordinate.
    ///
    /// # Errors
    /// Rejects unknown fields, noncanonical bytes, bounds, non-Clone requests,
    /// substituted assignment/origin or a renewed original deadline.
    pub fn decode(
        bytes: &[u8], peer: PeerCredentials, policy: PeerPolicy, now: u64,
    ) -> Result<Self, ProtocolValidationError> {
        if bytes.is_empty() || bytes.len() > NIX_GENERATION_REQUEST_MAXIMUM_BYTES_V1 {
            return Err(invalid("generation request bound"));
        }
        let request = PrepareNixStorageGenerationRequestV1::decode_from_slice(bytes)
            .map_err(|_| invalid("generation request protobuf"))?;
        if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != bytes
            || request.canonical_prepare.len() > 8_192
            || bytes.len().checked_sub(request.canonical_prepare.len())
                .is_none_or(|length| length > NIX_GENERATION_CONTEXT_MAXIMUM_BYTES_V1)
        {
            return Err(invalid("generation request canonical bytes"));
        }
        let prepare = CanonicalStoragePreparationSemanticsV1::decode(
            &request.canonical_prepare, peer, policy, now,
        ).map_err(|_| invalid("generation nested Prepare"))?;
        let nested = PrepareStorageCatalogRequest::decode_from_slice(&request.canonical_prepare)
            .map_err(|_| invalid("generation nested Prepare protobuf"))?;
        if nested.encode_to_vec() != request.canonical_prepare {
            return Err(invalid("generation nested Prepare canonical bytes"));
        }
        let prefix = NixGenerationStartPrefixV1::decode(&request.original_start_prefix)?;
        let origin = NixGenerationOriginV1::decode(&request.generation_origin)?;
        let StoragePreparationOperationV1::Clone {
            storage_handle, version_handle, hold_id, quota_bytes, reservation_bytes,
        } = prepare.operation() else {
            return Err(invalid("generation preparation must be Clone"));
        };
        let inventory = prepare.inventory_binding();
        let head = prepare.expected_catalog_head();
        let origin_digest: [u8; 32] = Sha256::digest(&request.generation_origin).into();
        if prefix.operation != prepare.operation_id()
            || prefix.sandbox != *prepare.fence().sandbox_id()
            || prefix.incarnation != *prepare.fence().incarnation_id()
            || prefix.assignment != *prepare.fence().assignment_digest()
            || prefix.origin != origin_digest
            || prefix.domain != origin.domain || prefix.project != origin.project
            || prefix.sandbox != origin.sandbox || prefix.incarnation != origin.incarnation
            || prefix.source_generation != origin.source_generation
            || prepare.header().deadline_boottime_nanoseconds()
                != prefix.deadline_boottime_nanoseconds
            || prepare.expires_boottime_nanoseconds() > prefix.deadline_boottime_nanoseconds
            || storage_handle != origin.storage_handle
            || version_handle != origin.source_version_handle || hold_id != origin.hold_id
            || quota_bytes != origin.quota_bytes || reservation_bytes != origin.reservation_bytes
            || inventory.generation() != origin.inventory_generation
            || inventory.digest().as_bytes() != &origin.inventory_digest
            || head.generation() != origin.catalog_generation
            || head.digest().as_bytes() != &origin.catalog_digest
        {
            return Err(invalid("generation preparation original crosslinks"));
        }
        Ok(Self {
            prepare, prefix, origin,
            commitment: BrokerArgumentCommitment::for_canonical_bytes(bytes),
        })
    }

    /// Borrows the original nested Clone comparison semantics.
    #[must_use]
    pub const fn prepare(&self) -> &CanonicalStoragePreparationSemanticsV1 { &self.prepare }

    /// Borrows original Start and deadline comparison DATA.
    #[must_use]
    pub const fn prefix(&self) -> &NixGenerationStartPrefixV1 { &self.prefix }

    /// Borrows independently provisioned predecessor comparison DATA.
    #[must_use]
    pub const fn origin(&self) -> &NixGenerationOriginV1 { &self.origin }

    /// Returns the commitment of the WHOLE canonical selected wrapper.
    #[must_use]
    pub const fn argument_commitment(&self) -> BrokerArgumentCommitment { self.commitment }
}

fn artifact_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    digest.finalize().into()
}

fn invalid(field: &'static str) -> ProtocolValidationError {
    ProtocolValidationError::InvalidField(field)
}

fn generation_read_error(_: ReadError) -> ProtocolValidationError {
    invalid("generation record truncation")
}

fn read_generation_fixed<const SIZE: usize>(
    reader: &mut BoundedReader<'_, ProtocolValidationError>,
) -> Result<[u8; SIZE], ProtocolValidationError> {
    reader
        .bytes(SIZE)?
        .try_into()
        .map_err(|_| invalid("generation record width"))
}

fn read_generation_variable<'bytes>(
    reader: &mut BoundedReader<'bytes, ProtocolValidationError>,
    maximum: usize,
) -> Result<&'bytes [u8], ProtocolValidationError> {
    let length = u32::from_be_bytes(read_generation_fixed(reader)?) as usize;
    if length > maximum {
        return Err(invalid("generation field bound"));
    }
    reader
        .bytes(length)
        .map_err(|_| invalid("generation field truncation"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original_prefix() -> NixGenerationStartPrefixV1 {
        NixGenerationStartPrefixV1 {
            operation: [1; 16],
            step: 0,
            assignment: [2; 32],
            desired: [3; 32],
            effect: [4; 32],
            recipe: [5; 32],
            input_set: [6; 32],
            presentation: [7; 32],
            domain: [8; 16],
            project: [9; 16],
            sandbox: [10; 16],
            incarnation: [11; 16],
            origin: [12; 32],
            source_generation: 19,
            next_generation: 20,
            host_boot_id: [13; 16],
            first_wall_seconds: 1_000,
            first_boottime_nanoseconds: 4_000,
            deadline_boottime_nanoseconds: 9_000,
        }
    }

    #[test]
    fn original_prefix_has_exact_fixed_width_and_roundtrip() {
        let prefix = original_prefix();
        let bytes = prefix.encode().unwrap();

        assert_eq!(bytes.len(), 372);
        assert_eq!(NixGenerationStartPrefixV1::decode(&bytes).unwrap(), prefix);
    }

    #[test]
    fn original_prefix_refuses_truncation_trailing_bytes_and_changed_generation() {
        let mut bytes = original_prefix().encode().unwrap();
        assert!(NixGenerationStartPrefixV1::decode(&bytes[..371]).is_err());

        bytes.push(0);
        assert!(NixGenerationStartPrefixV1::decode(&bytes).is_err());

        let mut changed = original_prefix();
        changed.next_generation += 1;
        assert!(changed.encode().is_err());
    }

    #[test]
    fn original_prefix_refuses_overflow_and_exclusive_deadline() {
        let mut prefix = original_prefix();
        prefix.source_generation = u64::MAX;
        assert!(prefix.encode().is_err());

        prefix = original_prefix();
        prefix.deadline_boottime_nanoseconds = prefix.first_boottime_nanoseconds;
        assert!(prefix.encode().is_err());
    }

    #[test]
    fn original_prefix_preserves_framing_errors_before_semantic_fields() {
        let mut bytes = original_prefix().encode().unwrap();
        bytes[8..24].fill(0);

        for length in 0..bytes.len() {
            assert!(matches!(
                NixGenerationStartPrefixV1::decode(&bytes[..length]),
                Err(ProtocolValidationError::InvalidField("generation record truncation"))
            ));
        }
        assert!(matches!(
            NixGenerationStartPrefixV1::decode(&bytes),
            Err(ProtocolValidationError::InvalidField("generation prefix coordinates"))
        ));

        bytes.push(0);
        assert!(matches!(
            NixGenerationStartPrefixV1::decode(&bytes),
            Err(ProtocolValidationError::InvalidField("generation trailing bytes"))
        ));
    }

    #[test]
    fn selected_wrapper_refuses_unknown_fields_and_oversized_added_context() {
        let mut unknown = PrepareNixStorageGenerationRequestV1::default().encode_to_vec();
        unknown.extend_from_slice(&[0x20, 1]);
        let peer = PeerCredentials { uid: 1000, gid: 1000, pid: None };
        let policy = PeerPolicy {
            uid: 1000,
            gid: Some(1000),
            audience: aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER,
        };

        assert!(CanonicalNixGenerationPreparationV1::decode(&unknown, peer, policy, 1).is_err());

        let oversized = PrepareNixStorageGenerationRequestV1 {
            original_start_prefix: vec![1; NIX_GENERATION_CONTEXT_MAXIMUM_BYTES_V1],
            ..Default::default()
        }.encode_to_vec();
        assert!(CanonicalNixGenerationPreparationV1::decode(&oversized, peer, policy, 1).is_err());
    }
}

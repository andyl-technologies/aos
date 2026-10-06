//! Canonical comparison meaning of the separately authorized Nix G0 population.
//!
//! This one encoder supplies population plan comparison and Storage request
//! verification. It does not install a request route or supply a paid issuer.
//! A decoded tuple neither resolves a workspace nor authenticates the seed,
//! birth, physical owner, lease, floor or resource reservation.
//!
//! ```text
//! AOSSNG01 | sandbox16 | incarnation16 | epoch8 | desired-generation8
//! assignment32 | population-operation16 | target-handle32 | Create-operation16
//! seed-descriptor-digest32 | birth-binding32 | complete-seed-Tree-digest32
//! reserved-zero8 = exactly256 bytes
//! ```

use aos_proto::aos::sandbox::local::v1::{
    PopulateStorageNixGenerationRootRequestV1, PopulateStorageNixGenerationRootResponseV1,
};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAssignment, BrokerGrantTarget, BrokerVerb, ProtocolId,
    ProtocolVersion,
};
use buffa::Message as _;

use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedAssignmentFence, ValidatedHeader,
    exact_nonzero, validate_fence, validate_request_header,
};

/// Bounds the complete selected protobuf body before comparison decoding.
pub const MAXIMUM_NIX_POPULATION_REQUEST_BYTES_V1: usize = 8192;
const CANONICAL_BYTES: usize = 256;
const MAGIC: &[u8; 8] = b"AOSSNG01";
const RECEIPT_MAGIC: &[u8; 8] = b"AOSNGP01";
const RECEIPT_BYTES: usize = 392;

/// Bounds the selected successful protobuf body separately from its BSA packet.
pub const MAXIMUM_NIX_POPULATION_RESPONSE_BYTES_V1: usize = 408;

/// Names comparison DATA that the real birth owner obtains from its originals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NixGenerationPopulationSelectionV1 {
    /// Original once-only population operation, distinct from Create.
    pub operation_id: [u8; 16],
    /// Actual preceding Create result retained by the same birth attempt.
    pub workspace_handle: [u8; 32],
    /// Original birth Create operation.
    pub creation_operation_id: [u8; 16],
    /// Digest of the complete independently supplied seed descriptor280.
    pub seed_descriptor_digest: [u8; 32],
    /// Digest of the complete original independently signed birth binding.
    pub birth_binding_digest: [u8; 32],
    /// Digest of the complete seed Tree independently bound by that artifact.
    pub seed_tree_digest: [u8; 32],
}

/// Retains one exact plan-match argument without producing effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalStorageNixGenerationArgumentsV1 {
    canonical_bytes: [u8; CANONICAL_BYTES],
}

impl CanonicalStorageNixGenerationArgumentsV1 {
    /// Encodes the real issuer's protected assignment and original selectors.
    ///
    /// # Errors
    /// Rejects zero/sentinel identities, invalid assignment coordinates and a
    /// population operation equal to the original Create operation.
    pub fn from_protected_assignment(
        assignment: BrokerAssignment,
        selection: NixGenerationPopulationSelectionV1,
    ) -> Result<Self, ProtocolValidationError> {
        Self::from_fields(
            *assignment.sandbox().as_bytes(),
            *assignment.incarnation().as_bytes(),
            assignment.epoch().get(),
            assignment.desired_generation().get(),
            *assignment.digest().as_bytes(),
            selection,
        )
    }

    fn from_fields(
        sandbox: [u8; 16],
        incarnation: [u8; 16],
        epoch: u64,
        desired_generation: u64,
        assignment_digest: [u8; 32],
        selection: NixGenerationPopulationSelectionV1,
    ) -> Result<Self, ProtocolValidationError> {
        if [
            sandbox,
            incarnation,
            selection.operation_id,
            selection.creation_operation_id,
        ]
        .iter()
        .any(|value| *value == [0; 16] || *value == [0xff; 16])
            || [
                assignment_digest,
                selection.workspace_handle,
                selection.seed_descriptor_digest,
                selection.birth_binding_digest,
                selection.seed_tree_digest,
            ]
            .iter()
            .any(|value| *value == [0; 32] || *value == [0xff; 32])
            || epoch == 0
            || epoch == u64::MAX
            || desired_generation == 0
            || desired_generation == u64::MAX
            || selection.operation_id == selection.creation_operation_id
        {
            return Err(ProtocolValidationError::InvalidField(
                "Nix population arguments",
            ));
        }

        let mut canonical_bytes = [0_u8; CANONICAL_BYTES];
        canonical_bytes[..8].copy_from_slice(MAGIC);
        canonical_bytes[8..24].copy_from_slice(&sandbox);
        canonical_bytes[24..40].copy_from_slice(&incarnation);
        canonical_bytes[40..48].copy_from_slice(&epoch.to_be_bytes());
        canonical_bytes[48..56].copy_from_slice(&desired_generation.to_be_bytes());
        canonical_bytes[56..88].copy_from_slice(&assignment_digest);
        canonical_bytes[88..104].copy_from_slice(&selection.operation_id);
        canonical_bytes[104..136].copy_from_slice(&selection.workspace_handle);
        canonical_bytes[136..152].copy_from_slice(&selection.creation_operation_id);
        canonical_bytes[152..184].copy_from_slice(&selection.seed_descriptor_digest);
        canonical_bytes[184..216].copy_from_slice(&selection.birth_binding_digest);
        canonical_bytes[216..248].copy_from_slice(&selection.seed_tree_digest);
        Ok(Self { canonical_bytes })
    }

    /// Borrows the exact complete AOSSNG01 argument, including reserved bytes.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; CANONICAL_BYTES] {
        &self.canonical_bytes
    }

    /// Computes the sole Core signed-plan argument commitment.
    #[must_use]
    pub fn argument_commitment(&self) -> BrokerArgumentCommitment {
        BrokerArgumentCommitment::for_canonical_bytes(&self.canonical_bytes)
    }
}

/// Retains the hostile request's checked meaning, not a birth or seed loan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalStorageNixGenerationSemanticsV1 {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    selection: NixGenerationPopulationSelectionV1,
    arguments: CanonicalStorageNixGenerationArgumentsV1,
}

impl CanonicalStorageNixGenerationSemanticsV1 {
    /// Validates the selected body's header/fence and uses the sole encoder.
    ///
    /// # Errors
    /// Rejects oversized, malformed, unknown-field, wrong-version, wrong-peer,
    /// expired, missing, sentinel or inconsistent request DATA.
    pub fn decode(
        bytes: &[u8],
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
    ) -> Result<Self, ProtocolValidationError> {
        if bytes.len() > MAXIMUM_NIX_POPULATION_REQUEST_BYTES_V1 {
            return Err(ProtocolValidationError::RequestTooLarge);
        }
        let request = PopulateStorageNixGenerationRootRequestV1::decode_from_slice(bytes)
            .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
        if !request.__buffa_unknown_fields.is_empty() {
            return Err(ProtocolValidationError::UnknownFields);
        }

        let header = validate_request_header(
            request
                .header
                .as_option()
                .ok_or(ProtocolValidationError::MissingField("header"))?,
            peer,
            policy,
            ProtocolId::StorageBroker,
            now_boottime_nanoseconds,
        )?;
        if header.protocol_version() != ProtocolVersion::new(1, 0) {
            return Err(ProtocolValidationError::MethodMismatch);
        }

        let fence = validate_fence(
            request
                .fence
                .as_option()
                .ok_or(ProtocolValidationError::MissingField("fence"))?,
        )?;
        let selection = NixGenerationPopulationSelectionV1 {
            operation_id: exact_nonzero(&request.operation_id, "operation_id")?,
            workspace_handle: exact_nonzero(&request.workspace_handle, "workspace_handle")?,
            creation_operation_id: exact_nonzero(
                &request.creation_operation_id,
                "creation_operation_id",
            )?,
            seed_descriptor_digest: exact_nonzero(
                &request.seed_descriptor_digest,
                "seed_descriptor_digest",
            )?,
            birth_binding_digest: exact_nonzero(
                &request.birth_binding_digest,
                "birth_binding_digest",
            )?,
            seed_tree_digest: exact_nonzero(&request.seed_tree_digest, "seed_tree_digest")?,
        };
        let arguments = CanonicalStorageNixGenerationArgumentsV1::from_fields(
            *fence.sandbox_id(),
            *fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.desired_generation(),
            *fence.assignment_digest(),
            selection,
        )?;

        Ok(Self {
            header,
            fence,
            selection,
            arguments,
        })
    }

    /// Borrows the same checked header used by authenticated carrier admission.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Borrows the complete exact assignment fence.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Borrows comparison selectors without exposing a physical owner.
    #[must_use]
    pub const fn selection(&self) -> &NixGenerationPopulationSelectionV1 {
        &self.selection
    }

    /// Borrows the exact signed-plan body produced by the sole encoder.
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; CANONICAL_BYTES] {
        self.arguments.canonical_bytes()
    }

    /// Computes the Core argument commitment using the sole canonical encoder.
    #[must_use]
    pub fn argument_commitment(&self) -> BrokerArgumentCommitment {
        self.arguments.argument_commitment()
    }

    /// Returns the separately allocated selected population purpose.
    #[must_use]
    pub const fn broker_verb(&self) -> BrokerVerb {
        BrokerVerb::StoragePopulateNixGenerationRoot
    }

    /// Returns the assignment scope; the actual target remains in the argument.
    #[must_use]
    pub const fn grant_target(&self) -> BrokerGrantTarget {
        BrokerGrantTarget::Assignment
    }
}

/// Carries the parent's original physical population observations as DATA.
///
/// These fields neither prove a current native floor nor grant a publication
/// or Snapshot. The genuine caller separately compares them with the admitted
/// seed, same workspace original, complete controls and final owner bookends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NixGenerationPopulationObservationV1 {
    /// Complete actual portable Tree digest after exclusive private copying.
    pub tree_digest: [u8; 32],
    /// Exact encoded size of that canonical Tree descriptor.
    pub tree_bytes: u64,
    /// Digest of the finalized actual private database control.
    pub database_digest: [u8; 32],
    /// Digest of the complete canonical actual four-control comparison map.
    pub controls_digest: [u8; 32],
    /// Actual target dataset GUID from the protected current postcondition.
    pub target_guid: u64,
    /// Actual original pinned mount identity used for the physical readback.
    pub mount_id: u64,
    /// Actual unique regular logical bytes in the complete physical projection.
    pub logical_bytes: u64,
}

/// Encodes one strictly request-bound population readback, never effect authority.
///
/// # Errors
/// Rejects an observation inconsistent with the signed Tree comparison or
/// reserved native sentinel values. It does not authenticate physical fields.
pub fn encode_nix_generation_population_receipt_v1(
    arguments: &CanonicalStorageNixGenerationArgumentsV1,
    observed: NixGenerationPopulationObservationV1,
) -> Result<[u8; RECEIPT_BYTES], ProtocolValidationError> {
    if observed.tree_digest != arguments.canonical_bytes()[216..248]
        || observed.tree_bytes == 0
        || observed.tree_bytes == u64::MAX
        || [observed.database_digest, observed.controls_digest]
            .iter()
            .any(|value| *value == [0; 32] || *value == [0xff; 32])
        || observed.target_guid == 0
        || observed.target_guid == u64::MAX
        || observed.mount_id == 0
        || observed.mount_id == u64::MAX
        || observed.logical_bytes == u64::MAX
    {
        return Err(ProtocolValidationError::InvalidField(
            "Nix population observation",
        ));
    }

    let mut receipt = [0_u8; RECEIPT_BYTES];
    receipt[..256].copy_from_slice(arguments.canonical_bytes());
    receipt[..8].copy_from_slice(RECEIPT_MAGIC);
    receipt[256..288].copy_from_slice(&observed.tree_digest);
    receipt[288..296].copy_from_slice(&observed.tree_bytes.to_be_bytes());
    receipt[296..328].copy_from_slice(&observed.database_digest);
    receipt[328..360].copy_from_slice(&observed.controls_digest);
    receipt[360..368].copy_from_slice(&observed.target_guid.to_be_bytes());
    receipt[368..376].copy_from_slice(&observed.mount_id.to_be_bytes());
    receipt[376..384].copy_from_slice(&observed.logical_bytes.to_be_bytes());
    Ok(receipt)
}

/// Decodes the selected response and compares every original request coordinate.
///
/// # Errors
/// Rejects excessive, unknown, malformed, sentinel, trailing or request-mismatched
/// DATA. The caller still requires the real final native/current owner and seed
/// control readback; a successfully decoded response is not population authority.
pub fn decode_storage_nix_generation_response_v1(
    bytes: &[u8],
    maximum_bytes: usize,
    original: &CanonicalStorageNixGenerationSemanticsV1,
) -> Result<NixGenerationPopulationObservationV1, ProtocolValidationError> {
    if bytes.len() > maximum_bytes.min(MAXIMUM_NIX_POPULATION_RESPONSE_BYTES_V1) {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = PopulateStorageNixGenerationRootResponseV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }

    let receipt = response.population_receipt.as_slice();
    if receipt.len() != RECEIPT_BYTES
        || receipt.get(..8) != Some(RECEIPT_MAGIC)
        || receipt[8..256] != original.canonical_bytes()[8..]
        || receipt[384..] != [0; 8]
    {
        return Err(ProtocolValidationError::InvalidField(
            "Nix population receipt",
        ));
    }

    let observed = NixGenerationPopulationObservationV1 {
        tree_digest: array(receipt, 256)?,
        tree_bytes: u64::from_be_bytes(array(receipt, 288)?),
        database_digest: array(receipt, 296)?,
        controls_digest: array(receipt, 328)?,
        target_guid: u64::from_be_bytes(array(receipt, 360)?),
        mount_id: u64::from_be_bytes(array(receipt, 368)?),
        logical_bytes: u64::from_be_bytes(array(receipt, 376)?),
    };
    if encode_nix_generation_population_receipt_v1(&original.arguments, observed)?
        .as_slice()
        != receipt
    {
        return Err(ProtocolValidationError::InvalidField(
            "Nix population canonical receipt",
        ));
    }

    Ok(observed)
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ProtocolValidationError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(ProtocolValidationError::InvalidField(
            "Nix population receipt width",
        ))
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::Audience;

    use super::*;

    fn decode(
        bytes: &[u8],
    ) -> Result<CanonicalStorageNixGenerationSemanticsV1, ProtocolValidationError> {
        CanonicalStorageNixGenerationSemanticsV1::decode(
            bytes,
            PeerCredentials {
                uid: 100,
                gid: 200,
                pid: Some(300),
            },
            PeerPolicy {
                uid: 100,
                gid: Some(200),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            100,
        )
    }

    fn selection() -> NixGenerationPopulationSelectionV1 {
        NixGenerationPopulationSelectionV1 {
            operation_id: [3; 16],
            workspace_handle: [4; 32],
            creation_operation_id: [5; 16],
            seed_descriptor_digest: [6; 32],
            birth_binding_digest: [7; 32],
            seed_tree_digest: [8; 32],
        }
    }

    #[test]
    fn population_argument_binds_the_complete_seed_and_birth() {
        let argument = CanonicalStorageNixGenerationArgumentsV1::from_fields(
            [1; 16],
            [2; 16],
            1,
            1,
            [9; 32],
            selection(),
        )
        .unwrap();

        assert_eq!(&argument.canonical_bytes()[..8], b"AOSSNG01");
        assert_eq!(&argument.canonical_bytes()[152..184], &[6; 32]);
        assert_eq!(&argument.canonical_bytes()[184..216], &[7; 32]);
        assert_eq!(&argument.canonical_bytes()[216..248], &[8; 32]);
        assert_eq!(&argument.canonical_bytes()[248..], &[0; 8]);
    }

    #[test]
    fn population_cannot_reuse_the_birth_create_operation() {
        let mut selected = selection();
        selected.operation_id = selected.creation_operation_id;

        assert!(CanonicalStorageNixGenerationArgumentsV1::from_fields(
            [1; 16],
            [2; 16],
            1,
            1,
            [9; 32],
            selected,
        )
        .is_err());
    }

    #[test]
    fn oversized_and_unknown_requests_close_before_header_validation() {
        assert!(matches!(
            decode(&vec![0; MAXIMUM_NIX_POPULATION_REQUEST_BYTES_V1 + 1]),
            Err(ProtocolValidationError::RequestTooLarge),
        ));

        // Field9 is unknown in V1 even when its byte string is empty.
        assert!(matches!(
            decode(&[0x4a, 0]),
            Err(ProtocolValidationError::UnknownFields),
        ));
        assert!(matches!(
            decode(&[0x4a]),
            Err(ProtocolValidationError::MalformedWire(_)),
        ));
    }

    #[test]
    fn original_assignment_and_receipt_share_one_canonical_argument() {
        let mut request = PopulateStorageNixGenerationRootRequestV1::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.request_id = vec![10; 16];
        header.deadline_boottime_nanoseconds = 200;
        header.maximum_response_bytes = 4096;

        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![1; 16];
        fence.incarnation_id = vec![2; 16];
        fence.assignment_epoch = 1;
        fence.desired_generation = 1;
        fence.assignment_digest = vec![9; 32];
        let selected = selection();
        request.operation_id = selected.operation_id.to_vec();
        request.workspace_handle = selected.workspace_handle.to_vec();
        request.creation_operation_id = selected.creation_operation_id.to_vec();
        request.seed_descriptor_digest = selected.seed_descriptor_digest.to_vec();
        request.birth_binding_digest = selected.birth_binding_digest.to_vec();
        request.seed_tree_digest = selected.seed_tree_digest.to_vec();

        let original = decode(&request.encode_to_vec()).unwrap();
        let arguments = CanonicalStorageNixGenerationArgumentsV1::from_protected_assignment(
            original.fence().broker_assignment().unwrap(),
            selected,
        )
        .unwrap();
        assert_eq!(arguments.canonical_bytes(), original.canonical_bytes());

        let observed = NixGenerationPopulationObservationV1 {
            tree_digest: selected.seed_tree_digest,
            tree_bytes: 40,
            database_digest: [11; 32],
            controls_digest: [12; 32],
            target_guid: 13,
            mount_id: 14,
            logical_bytes: 42,
        };
        let receipt = encode_nix_generation_population_receipt_v1(&arguments, observed).unwrap();
        assert_eq!(receipt.len(), 392);
        assert_eq!(&receipt[384..], &[0; 8]);

        let mut response = PopulateStorageNixGenerationRootResponseV1::default();
        response.population_receipt = receipt.to_vec();
        assert_eq!(
            decode_storage_nix_generation_response_v1(
                &response.encode_to_vec(),
                MAXIMUM_NIX_POPULATION_RESPONSE_BYTES_V1,
                &original,
            )
            .unwrap(),
            observed,
        );

        response.population_receipt[384] = 1;
        assert!(decode_storage_nix_generation_response_v1(
            &response.encode_to_vec(),
            MAXIMUM_NIX_POPULATION_RESPONSE_BYTES_V1,
            &original,
        )
        .is_err());
    }
}

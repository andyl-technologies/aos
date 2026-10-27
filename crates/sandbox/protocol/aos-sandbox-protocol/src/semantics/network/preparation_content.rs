//! Frames exact assignment and specification bytes for Network preparation.
//!
//! The authenticated Prepare binds the complete sealed content by length and
//! SHA-256. Framing does not establish canonical model validity, currentness,
//! protected reservation, or permission to create a namespace. The receiving
//! Network owner validates both models with its existing reservation engine.
//!
//! ```text
//! AOSNPC02 | manifest-length:u32be | specification-length:u32be |
//! exact-canonical-assignment-manifest | exact-canonical-sandbox-specification
//! ```

use aos_sandbox_api::aos::sandbox::local::v1::{
    ApplyNetworkRequest, AssignmentFence, Audience, BrokerDescriptorRole, NetworkAction,
    RequestHeader,
};
use aos_sandbox_model::{BrokerAssignment, DecodeLimits, NetworkEndpointId, ObjectDigest};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::NetworkSemanticsError;

const MAGIC: &[u8; 8] = b"AOSNPC02";
const PREFIX_BYTES: usize = 16;

/// Validates and encodes the specification paired with a Network manifest.
///
/// This is the common portable comparison used before Root plan construction
/// and protected Network reservation. It proves no live admission or custody.
///
/// # Errors
/// Rejects descriptor, environment or root mismatches and host networking.
pub fn canonical_network_preparation_specification_v2(
    manifest: &aos_sandbox_model::CanonicalAssignmentManifestV1,
    specification: &aos_sandbox_model::model::SandboxSpec,
) -> Result<Vec<u8>, NetworkSemanticsError> {
    use aos_sandbox_model::{descriptor_for_bytes, encode_sandbox_spec, sandbox_spec_media_type};

    let model = manifest.manifest();
    let bytes = encode_sandbox_spec(specification);
    let observed = descriptor_for_bytes(model.sandbox_spec().media_type().clone(), &bytes);
    if observed != *model.sandbox_spec()
        || model.sandbox_spec().media_type().as_str()
            != sandbox_spec_media_type(specification).as_str()
        || specification.environment() != model.environment()
        || specification.root_view() != model.root_view()
        || specification.network_profile().kind() == aos_sandbox_model::model::NetworkKind::Host
    {
        return Err(NetworkSemanticsError::InvalidActionShape);
    }

    Ok(bytes)
}

/// Bounds the exact preparation's two canonical models before either decode.
///
/// The caller separately pays the retained sealed input and native reader.
/// This invoice joins the actual Core assignment and specification decoder
/// suppliers and their canonical comparison bytes. It uses the same default
/// Core limits as the actual Network reservation rather than Storage's smaller
/// metadata policy. Named source, feature and profile rows are bounded by
/// disjoint encoded items; decoder controls add no namespace entries.
///
/// Returns `None` for an oversized operand or checked arithmetic overflow.
#[must_use]
pub fn network_preparation_models_receiving_obligations_v2(
    manifest_bytes: usize,
    specification_bytes: usize,
) -> Option<(usize, usize)> {
    use aos_sandbox_model::format::{
        assignment_capture::CanonicalAssignmentDecodeCaptureV1,
        sandbox_spec_decoding_receiving_bytes_v2,
    };

    let limits = DecodeLimits::default();
    if manifest_bytes > limits.maximum_bytes || specification_bytes > limits.maximum_bytes {
        return None;
    }
    let (assignment, _) = CanonicalAssignmentDecodeCaptureV1::receiving_dynamic_footprint_v1(
        manifest_bytes, limits,
    )?;
    let assignment = assignment.checked_add(
        CanonicalAssignmentDecodeCaptureV1::receiving_construction_bytes_v1()?,
    )?;
    let specification = sandbox_spec_decoding_receiving_bytes_v2(specification_bytes, limits)?;
    let bytes = assignment.checked_add(specification)?
        .checked_add(manifest_bytes.checked_mul(2)?)?;
    let names = manifest_bytes.min(limits.maximum_total_items)
        .checked_add(specification_bytes.min(limits.maximum_total_items))?;
    Some((bytes, names))
}

/// Names the sole request descriptor accepted by version-two Prepare.
pub const NETWORK_PREPARATION_DESCRIPTOR_ROLES_V2: [BrokerDescriptorRole; 1] =
    [BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_NETWORK_PREPARATION_V2];

/// Borrows the two exact model encodings carried by one sealed preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkPreparationContentV2<'content> {
    manifest: &'content [u8],
    specification: &'content [u8],
}

impl<'content> NetworkPreparationContentV2<'content> {
    /// Returns framing plus both existing core decoder byte ceilings.
    #[must_use]
    pub fn maximum_encoded_bytes() -> usize {
        PREFIX_BYTES + 2 * DecodeLimits::default().maximum_bytes
    }

    /// Borrows bounded nonempty model encodings without adopting their authority.
    ///
    /// # Errors
    /// Rejects empty inputs or an input above the existing core decoder limit.
    pub fn new(
        manifest: &'content [u8],
        specification: &'content [u8],
    ) -> Result<Self, NetworkSemanticsError> {
        let maximum = DecodeLimits::default().maximum_bytes;
        if manifest.is_empty()
            || specification.is_empty()
            || manifest.len() > maximum
            || specification.len() > maximum
        {
            return Err(NetworkSemanticsError::InvalidActionShape);
        }

        Ok(Self {
            manifest,
            specification,
        })
    }

    /// Parses exact framing without allocating or decoding the model bodies.
    ///
    /// # Errors
    /// Rejects old formats, malformed lengths, trailing bytes or oversized inputs.
    pub fn decode(bytes: &'content [u8]) -> Result<Self, NetworkSemanticsError> {
        if bytes.len() < PREFIX_BYTES || bytes[..8] != *MAGIC {
            return Err(NetworkSemanticsError::InvalidActionShape);
        }

        let manifest = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| NetworkSemanticsError::InvalidActionShape)?,
        ) as usize;
        let specification = u32::from_be_bytes(
            bytes[12..16]
                .try_into()
                .map_err(|_| NetworkSemanticsError::InvalidActionShape)?,
        ) as usize;
        let split = PREFIX_BYTES
            .checked_add(manifest)
            .ok_or(NetworkSemanticsError::InvalidActionShape)?;
        if split.checked_add(specification) != Some(bytes.len()) {
            return Err(NetworkSemanticsError::InvalidActionShape);
        }

        Self::new(&bytes[PREFIX_BYTES..split], &bytes[split..])
    }

    /// Returns the complete encoded width before allocating its destination.
    #[must_use]
    pub fn encoded_bytes(self) -> usize {
        // Each validated operand is at most the existing 64 MiB decoder bound.
        PREFIX_BYTES + self.manifest.len() + self.specification.len()
    }

    /// Encodes the exact content after its caller admits the destination space.
    ///
    /// # Errors
    /// Rejects lengths which cannot be represented in the framing fields.
    pub fn encode(self) -> Result<Vec<u8>, NetworkSemanticsError> {
        let manifest = u32::try_from(self.manifest.len())
            .map_err(|_| NetworkSemanticsError::InvalidActionShape)?;
        let specification = u32::try_from(self.specification.len())
            .map_err(|_| NetworkSemanticsError::InvalidActionShape)?;
        let mut bytes = Vec::with_capacity(self.encoded_bytes());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&manifest.to_be_bytes());
        bytes.extend_from_slice(&specification.to_be_bytes());
        bytes.extend_from_slice(self.manifest);
        bytes.extend_from_slice(self.specification);

        Ok(bytes)
    }

    /// Returns the unverified canonical assignment-manifest bytes.
    #[must_use]
    pub const fn manifest_bytes(self) -> &'content [u8] {
        self.manifest
    }

    /// Returns the unverified canonical sandbox-specification bytes.
    #[must_use]
    pub const fn specification_bytes(self) -> &'content [u8] {
        self.specification
    }
}

/// Binds one version-two request to the exact sealed preparation bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkPreparationContentReferenceV2 {
    bytes: u64,
    digest: ObjectDigest,
}

impl NetworkPreparationContentReferenceV2 {
    /// Derives a reference from a complete framed preparation.
    ///
    /// # Errors
    /// Rejects malformed content before producing its digest.
    pub fn for_content(bytes: &[u8]) -> Result<Self, NetworkSemanticsError> {
        NetworkPreparationContentV2::decode(bytes)?;
        Ok(Self {
            bytes: bytes.len() as u64,
            digest: ObjectDigest::from_bytes(Sha256::digest(bytes).into()),
        })
    }

    pub(super) fn from_request(
        request: &ApplyNetworkRequest,
    ) -> Result<Self, NetworkSemanticsError> {
        let maximum = NetworkPreparationContentV2::maximum_encoded_bytes();
        if request.prepare_content_version != 2
            || request.prepare_content_bytes < (PREFIX_BYTES + 2) as u64
            || request.prepare_content_bytes > maximum as u64
        {
            return Err(NetworkSemanticsError::InvalidActionShape);
        }
        let digest =
            crate::exact_nonzero::<32>(&request.prepare_content_digest, "prepare_content_digest")?;

        Ok(Self {
            bytes: request.prepare_content_bytes,
            digest: ObjectDigest::from_bytes(digest),
        })
    }

    /// Writes the three framing fields without authorizing the request.
    pub fn bind_request(self, request: &mut ApplyNetworkRequest) {
        request.prepare_content_version = 2;
        request.prepare_content_bytes = self.bytes;
        request.prepare_content_digest = self.digest.as_bytes().to_vec();
    }

    /// Encodes an inert Prepare template for the sole authenticated method.
    ///
    /// The exact same template is normalized by Controller and Root. Its
    /// deadline remains absent until the existing admitted attempt framer
    /// inserts the original, possibly narrower Root cutoff. Neither this
    /// constructor nor its signed-input digest supplies a dispatch grant.
    ///
    /// # Errors
    /// Rejects reserved request identities, noncanonical endpoint sets or
    /// a body beyond the existing request ceiling.
    pub fn deadline_free_request_body_v2(
        self,
        assignment: BrokerAssignment,
        request_id: [u8; 16],
        endpoints: &[NetworkEndpointId],
    ) -> Result<Vec<u8>, NetworkSemanticsError> {
        if request_id == [0; 16] || endpoints.len() > super::MAXIMUM_NETWORK_ENDPOINTS {
            return Err(NetworkSemanticsError::InvalidActionShape);
        }
        if endpoints.windows(2).any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
            || endpoints.iter().any(|endpoint| endpoint.as_bytes() == &[0; 16])
        {
            return Err(NetworkSemanticsError::InvalidActionShape);
        }

        let mut request = ApplyNetworkRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: request_id.to_vec(),
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                maximum_response_bytes: crate::MINIMUM_RESPONSE_BYTES,
                ..Default::default()
            }).into(),
            fence: Some(AssignmentFence {
                sandbox_id: assignment.sandbox().as_bytes().to_vec(),
                incarnation_id: assignment.incarnation().as_bytes().to_vec(),
                assignment_epoch: assignment.epoch().get(),
                desired_generation: assignment.desired_generation().get(),
                assignment_digest: assignment.digest().as_bytes().to_vec(),
                ..Default::default()
            }).into(),
            action: NetworkAction::NETWORK_ACTION_PREPARE.into(),
            endpoint_ids: endpoints.iter().map(|endpoint| endpoint.as_bytes().to_vec()).collect(),
            ..Default::default()
        };
        self.bind_request(&mut request);
        let bytes = request.encode_to_vec();
        if bytes.len() > crate::MAXIMUM_REQUEST_BYTES {
            return Err(NetworkSemanticsError::CanonicalEncodingTooLarge);
        }

        Ok(bytes)
    }

    /// Compares the complete actual sealed bytes with this signed reference.
    ///
    /// # Errors
    /// Rejects wrong lengths, digests, old formats or malformed framing.
    pub fn verify<'content>(
        self,
        bytes: &'content [u8],
    ) -> Result<NetworkPreparationContentV2<'content>, NetworkSemanticsError> {
        if bytes.len() as u64 != self.bytes
            || Sha256::digest(bytes).as_slice() != self.digest.as_bytes()
        {
            return Err(NetworkSemanticsError::InvalidActionShape);
        }
        NetworkPreparationContentV2::decode(bytes)
    }

    /// Returns the exact sealed byte count.
    #[must_use]
    pub const fn content_bytes(self) -> u64 {
        self.bytes
    }

    /// Returns the SHA-256 of the complete sealed content.
    #[must_use]
    pub const fn content_digest(self) -> ObjectDigest {
        self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_rejects_rebinding_either_original_operand() {
        let content = NetworkPreparationContentV2::new(b"manifest", b"specification")
            .unwrap()
            .encode()
            .unwrap();
        let reference = NetworkPreparationContentReferenceV2::for_content(&content).unwrap();
        assert_eq!(
            reference.verify(&content).unwrap().manifest_bytes(),
            b"manifest"
        );

        for index in [PREFIX_BYTES, content.len() - 1] {
            let mut changed = content.clone();
            changed[index] ^= 1;
            assert!(reference.verify(&changed).is_err());
        }
        let mut trailing = content.clone();
        trailing.push(0);
        assert!(reference.verify(&trailing).is_err());
        assert!(NetworkPreparationContentV2::decode(&trailing).is_err());
    }

    #[test]
    fn framing_rejects_old_empty_overflow_and_truncated_inputs() {
        let content = NetworkPreparationContentV2::new(b"m", b"s")
            .unwrap()
            .encode()
            .unwrap();
        for length in 0..content.len() {
            assert!(NetworkPreparationContentV2::decode(&content[..length]).is_err());
        }
        for (range, replacement) in [
            (0..8, b"AOSNPC01".as_slice()),
            (8..12, u32::MAX.to_be_bytes().as_slice()),
            (12..16, 0_u32.to_be_bytes().as_slice()),
        ] {
            let mut malformed = content.clone();
            malformed[range].copy_from_slice(replacement);
            assert!(NetworkPreparationContentV2::decode(&malformed).is_err());
        }
        assert!(NetworkPreparationContentV2::new(b"", b"s").is_err());
    }
}

#[cfg(test)]
mod receiving_tests {
    use super::*;

    #[test]
    fn receiving_preserves_network_operand_limits_and_actual_extent() {
        let small = network_preparation_models_receiving_obligations_v2(16_384, 16_384).unwrap();
        let large = network_preparation_models_receiving_obligations_v2(524_288, 524_288).unwrap();
        assert!(large.0 > small.0);
        assert!(large.1 > small.1);
        let ceiling = DecodeLimits::default().maximum_bytes;
        assert!(network_preparation_models_receiving_obligations_v2(ceiling, ceiling).is_some());
        assert!(network_preparation_models_receiving_obligations_v2(ceiling + 1, 1).is_none());
        assert!(network_preparation_models_receiving_obligations_v2(1, usize::MAX).is_none());
    }
}

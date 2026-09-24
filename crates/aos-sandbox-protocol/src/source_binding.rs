//! Canonical logical authority for one realized filesystem-view source.
//!
//! A source realization binding joins the portable source selector to the
//! exact view identity and descriptor that authorized it. Mount uses its
//! domain-separated digest as the only logical key for provider attestations,
//! broker-owned source pins, durable recipes, and inventory correlation.
//! Paths and kernel descriptors are deliberately absent from this value.

use aos_proto::aos::sandbox::local::v1::MountSourceConsistency;
use aos_sandbox_core::{
    DecodeLimits, DescriptorRole, MediaType, ObjectDescriptor, ObjectDigest, decode_view_source,
    encode_view_source, model::ViewSource, validate_descriptor_role,
};
use aos_sandbox_source_provider_protocol::SourceProviderProofV1;
use sha2::{Digest as _, Sha256};

const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.mount.source-realization-binding.v1\0";
const FORMAT_VERSION: u16 = 1;

/// Reports a malformed or internally inconsistent source realization binding.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceBindingError {
    /// A required identity or revision uses its reserved zero sentinel.
    #[error("source binding {0} is absent or zero")]
    Missing(&'static str),
    /// The view descriptor is not a registered filesystem-view revision.
    #[error("source binding view descriptor is invalid: {0}")]
    InvalidViewDescriptor(String),
    /// The immutable source descriptor is not a registered tree source.
    #[error("source binding immutable source descriptor is invalid: {0}")]
    InvalidSourceDescriptor(String),
    /// The logical source variant contradicts consistency or incarnation data.
    #[error("source binding logical source, consistency, and incarnation disagree")]
    IncompatibleSource,
    /// Canonical bytes are truncated, overlong, unknown-version, or malformed.
    #[error("source binding canonical bytes are malformed")]
    MalformedCanonical,
}

/// Binds one path-free logical source to an exact filesystem-view revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRealizationBindingV1 {
    source_view_id: [u8; 16],
    source_view_revision: u64,
    view_descriptor: ObjectDescriptor,
    source: ViewSource,
    consistency: MountSourceConsistency,
    source_incarnation_id: Option<[u8; 16]>,
}

impl SourceRealizationBindingV1 {
    /// Constructs and validates one complete logical source authority tuple.
    ///
    /// # Errors
    ///
    /// Returns [`SourceBindingError`] for zero identities or revisions, an
    /// invalid view descriptor role, or a source variant inconsistent with the
    /// selected native consistency and optional live incarnation.
    pub fn new(
        source_view_id: [u8; 16],
        source_view_revision: u64,
        view_descriptor: ObjectDescriptor,
        source: ViewSource,
        consistency: MountSourceConsistency,
        source_incarnation_id: Option<[u8; 16]>,
    ) -> Result<Self, SourceBindingError> {
        if source_view_id == [0; 16] {
            return Err(SourceBindingError::Missing("source view identity"));
        }
        if source_view_revision == 0 {
            return Err(SourceBindingError::Missing("source view revision"));
        }
        if source_incarnation_id == Some([0; 16]) {
            return Err(SourceBindingError::Missing("source incarnation identity"));
        }
        validate_descriptor_role(DescriptorRole::FilesystemViewRevision, &view_descriptor)
            .map_err(|error| SourceBindingError::InvalidViewDescriptor(error.to_string()))?;
        if view_descriptor.digest().as_bytes() == &[0; 32] || view_descriptor.encoded_size() == 0 {
            return Err(SourceBindingError::Missing("view descriptor identity"));
        }

        let compatible = match &source {
            ViewSource::ImmutableTree { tree } => {
                validate_descriptor_role(DescriptorRole::ImmutableViewSource, tree).map_err(
                    |error| SourceBindingError::InvalidSourceDescriptor(error.to_string()),
                )?;
                consistency == MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
                    && source_incarnation_id.is_none()
                    && tree.digest().as_bytes() != &[0; 32]
                    && tree.encoded_size() != 0
            }
            ViewSource::LiveExport {
                owner_sandbox,
                export,
                source_generation,
            } => {
                matches!(
                    consistency,
                    MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE
                        | MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA
                ) && (source_incarnation_id.is_some()
                    == (consistency == MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE))
                    && owner_sandbox.as_bytes() != &[0; 16]
                    && export.as_bytes() != &[0; 16]
                    && source_generation.get() != 0
            }
        };
        if !compatible {
            return Err(SourceBindingError::IncompatibleSource);
        }

        Ok(Self {
            source_view_id,
            source_view_revision,
            view_descriptor,
            source,
            consistency,
            source_incarnation_id,
        })
    }

    /// Returns the logical source-view identity.
    #[must_use]
    pub const fn source_view_id(&self) -> &[u8; 16] {
        &self.source_view_id
    }

    /// Returns the exact source-view revision or generation.
    #[must_use]
    pub const fn source_view_revision(&self) -> u64 {
        self.source_view_revision
    }

    /// Returns the exact portable filesystem-view descriptor.
    #[must_use]
    pub const fn view_descriptor(&self) -> &ObjectDescriptor {
        &self.view_descriptor
    }

    /// Returns the canonical path-free logical source.
    #[must_use]
    pub const fn source(&self) -> &ViewSource {
        &self.source
    }

    /// Returns the closed native source consistency class.
    #[must_use]
    pub const fn consistency(&self) -> MountSourceConsistency {
        self.consistency
    }

    /// Returns the required local-live incarnation, when present.
    #[must_use]
    pub const fn source_incarnation_id(&self) -> Option<&[u8; 16]> {
        self.source_incarnation_id.as_ref()
    }

    /// Checks that a provider's live export grant names this exact View source.
    ///
    /// The provider verifies the export lease and kernel grant independently.
    /// This check prevents a valid grant for another export or incarnation from
    /// satisfying a binding that only happened to request the LocalLive class.
    #[must_use]
    pub fn matches_local_live_provider_proof(&self, proof: &SourceProviderProofV1) -> bool {
        let (
            ViewSource::LiveExport {
                owner_sandbox,
                export,
                source_generation,
            },
            SourceProviderProofV1::LocalLiveExport { proof, .. },
            Some(source_incarnation),
        ) = (&self.source, proof, self.source_incarnation_id)
        else {
            return false;
        };

        self.consistency == MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE
            && proof.owner_sandbox() == *owner_sandbox.as_bytes()
            && proof.source_incarnation() == source_incarnation
            && proof.export_id() == *export.as_bytes()
            && proof.export_generation() == source_generation.get()
    }

    /// Encodes the complete tuple in one deterministic versioned byte form.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let media_type = self.view_descriptor.media_type().as_str().as_bytes();
        let source = encode_view_source(&self.source);
        let mut bytes =
            Vec::with_capacity(2 + 16 + 8 + 2 + media_type.len() + 32 + 8 + 4 + source.len() + 18);

        bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.source_view_id);
        bytes.extend_from_slice(&self.source_view_revision.to_be_bytes());
        bytes.extend_from_slice(
            &u64::try_from(media_type.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(media_type);
        bytes.extend_from_slice(self.view_descriptor.digest().as_bytes());
        bytes.extend_from_slice(&self.view_descriptor.encoded_size().to_be_bytes());
        bytes.extend_from_slice(
            &u64::try_from(source.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&source);
        bytes.push(consistency_code(self.consistency));
        match self.source_incarnation_id {
            Some(incarnation) => {
                bytes.push(1);
                bytes.extend_from_slice(&incarnation);
            }
            None => bytes.push(0),
        }
        bytes
    }

    /// Decodes and revalidates one exact canonical binding byte string.
    ///
    /// # Errors
    ///
    /// Returns [`SourceBindingError`] for truncation, trailing data, unknown
    /// versions or closed codes, noncanonical lengths, malformed source CBOR,
    /// invalid descriptors, sentinels, or incompatible source semantics.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SourceBindingError> {
        let mut decoder = BindingDecoder::new(bytes);
        if decoder.u16()? != FORMAT_VERSION {
            return Err(SourceBindingError::MalformedCanonical);
        }
        let source_view_id = decoder.array()?;
        let source_view_revision = decoder.u64()?;
        let media_length = decoder.length()?;
        let media_type = std::str::from_utf8(decoder.bytes(media_length)?)
            .map_err(|_| SourceBindingError::MalformedCanonical)?;
        let media_type = MediaType::new(media_type.to_owned())
            .map_err(|_| SourceBindingError::MalformedCanonical)?;
        let view_digest = ObjectDigest::from_bytes(decoder.array()?);
        let encoded_size = decoder.u64()?;
        let source_length = decoder.length()?;
        let source_bytes = decoder.bytes(source_length)?;
        let source = decode_view_source(source_bytes, DecodeLimits::default())
            .map_err(|_| SourceBindingError::MalformedCanonical)?;
        if encode_view_source(&source) != source_bytes {
            return Err(SourceBindingError::MalformedCanonical);
        }
        let consistency = match decoder.byte()? {
            1 => MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
            2 => MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
            4 => MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA,
            _ => return Err(SourceBindingError::MalformedCanonical),
        };
        let source_incarnation_id = match decoder.byte()? {
            0 => None,
            1 => Some(decoder.array()?),
            _ => return Err(SourceBindingError::MalformedCanonical),
        };
        decoder.finish()?;

        let binding = Self::new(
            source_view_id,
            source_view_revision,
            ObjectDescriptor::new(media_type, view_digest, encoded_size),
            source,
            consistency,
            source_incarnation_id,
        )?;
        if binding.canonical_bytes() != bytes {
            return Err(SourceBindingError::MalformedCanonical);
        }
        Ok(binding)
    }

    /// Returns the domain-separated SHA-256 identity of this complete tuple.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let mut digest = Sha256::new();
        digest.update(DIGEST_DOMAIN);
        digest.update(self.canonical_bytes());
        ObjectDigest::from_bytes(digest.finalize().into())
    }
}

struct BindingDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BindingDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], SourceBindingError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SourceBindingError::MalformedCanonical)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SourceBindingError::MalformedCanonical)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SourceBindingError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| SourceBindingError::MalformedCanonical)
    }

    fn byte(&mut self) -> Result<u8, SourceBindingError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, SourceBindingError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, SourceBindingError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn length(&mut self) -> Result<usize, SourceBindingError> {
        usize::try_from(self.u64()?).map_err(|_| SourceBindingError::MalformedCanonical)
    }

    fn finish(self) -> Result<(), SourceBindingError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SourceBindingError::MalformedCanonical)
        }
    }
}

const fn consistency_code(consistency: MountSourceConsistency) -> u8 {
    match consistency {
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION => 1,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE => 2,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_TRANSACTIONAL_SERVICE => 3,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA => 4,
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_UNSPECIFIED => 0,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::{ExportId, MediaType, Revision, SandboxId};
    use aos_sandbox_source_provider_protocol::{LocalLiveExportProofV1, RecursiveTopologyProofV1};

    use super::*;

    fn descriptor(byte: u8, size: u64) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.view.v1+cbor".to_owned()).unwrap(),
            ObjectDigest::from_bytes([byte; 32]),
            size,
        )
    }

    fn live_binding() -> SourceRealizationBindingV1 {
        SourceRealizationBindingV1::new(
            [1; 16],
            2,
            descriptor(3, 4),
            ViewSource::LiveExport {
                owner_sandbox: SandboxId::from_bytes([5; 16]),
                export: ExportId::from_bytes([6; 16]),
                source_generation: Revision::new(7),
            },
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
            Some([8; 16]),
        )
        .unwrap()
    }

    fn live_proof(
        owner: [u8; 16],
        incarnation: [u8; 16],
        export: [u8; 16],
        generation: u64,
    ) -> SourceProviderProofV1 {
        SourceProviderProofV1::LocalLiveExport {
            proof: LocalLiveExportProofV1::new(
                ObjectDigest::from_bytes([9; 32]),
                owner,
                incarnation,
                export,
                generation,
                ObjectDigest::from_bytes([10; 32]),
                ObjectDigest::from_bytes([11; 32]),
                [12; 16],
                13,
                ObjectDigest::from_bytes([14; 32]),
                [15; 32],
                ObjectDigest::from_bytes([16; 32]),
            )
            .unwrap(),
            topology: RecursiveTopologyProofV1::new(
                [17; 16],
                18,
                ObjectDigest::from_bytes([19; 32]),
                20,
                21,
                1,
                0,
            )
            .unwrap(),
        }
    }

    #[test]
    fn local_live_grant_must_match_exact_view_source() {
        let binding = live_binding();
        assert!(
            binding.matches_local_live_provider_proof(&live_proof([5; 16], [8; 16], [6; 16], 7,))
        );
        for proof in [
            live_proof([9; 16], [8; 16], [6; 16], 7),
            live_proof([5; 16], [9; 16], [6; 16], 7),
            live_proof([5; 16], [8; 16], [9; 16], 7),
            live_proof([5; 16], [8; 16], [6; 16], 9),
        ] {
            assert!(!binding.matches_local_live_provider_proof(&proof));
        }
    }

    #[test]
    fn every_authority_field_changes_the_binding_digest() {
        let original = live_binding();
        let candidates = [
            SourceRealizationBindingV1::new(
                [9; 16],
                2,
                descriptor(3, 4),
                original.source.clone(),
                original.consistency,
                Some([8; 16]),
            )
            .unwrap(),
            SourceRealizationBindingV1::new(
                [1; 16],
                9,
                descriptor(3, 4),
                original.source.clone(),
                original.consistency,
                Some([8; 16]),
            )
            .unwrap(),
            SourceRealizationBindingV1::new(
                [1; 16],
                2,
                descriptor(9, 4),
                original.source.clone(),
                original.consistency,
                Some([8; 16]),
            )
            .unwrap(),
            SourceRealizationBindingV1::new(
                [1; 16],
                2,
                descriptor(3, 9),
                original.source.clone(),
                original.consistency,
                Some([8; 16]),
            )
            .unwrap(),
            SourceRealizationBindingV1::new(
                [1; 16],
                2,
                descriptor(3, 4),
                ViewSource::LiveExport {
                    owner_sandbox: SandboxId::from_bytes([9; 16]),
                    export: ExportId::from_bytes([6; 16]),
                    source_generation: Revision::new(7),
                },
                original.consistency,
                Some([8; 16]),
            )
            .unwrap(),
            SourceRealizationBindingV1::new(
                [1; 16],
                2,
                descriptor(3, 4),
                ViewSource::LiveExport {
                    owner_sandbox: SandboxId::from_bytes([5; 16]),
                    export: ExportId::from_bytes([9; 16]),
                    source_generation: Revision::new(7),
                },
                original.consistency,
                Some([8; 16]),
            )
            .unwrap(),
            SourceRealizationBindingV1::new(
                [1; 16],
                2,
                descriptor(3, 4),
                ViewSource::LiveExport {
                    owner_sandbox: SandboxId::from_bytes([5; 16]),
                    export: ExportId::from_bytes([6; 16]),
                    source_generation: Revision::new(9),
                },
                original.consistency,
                Some([8; 16]),
            )
            .unwrap(),
            SourceRealizationBindingV1::new(
                [1; 16],
                2,
                descriptor(3, 4),
                original.source.clone(),
                original.consistency,
                Some([9; 16]),
            )
            .unwrap(),
            SourceRealizationBindingV1::new(
                [1; 16],
                2,
                descriptor(3, 4),
                original.source.clone(),
                MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA,
                None,
            )
            .unwrap(),
        ];

        for candidate in candidates {
            assert_ne!(candidate.digest(), original.digest());
        }
    }

    #[test]
    fn canonical_binding_round_trips_and_rejects_every_truncation() {
        let binding = live_binding();
        let bytes = binding.canonical_bytes();
        assert_eq!(
            SourceRealizationBindingV1::from_canonical_bytes(&bytes).unwrap(),
            binding
        );

        for length in 0..bytes.len() {
            assert!(
                SourceRealizationBindingV1::from_canonical_bytes(&bytes[..length]).is_err(),
                "accepted truncation at {length}"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(SourceRealizationBindingV1::from_canonical_bytes(&trailing).is_err());
    }

    #[test]
    fn variant_consistency_and_incarnation_mismatches_fail_closed() {
        let immutable = ViewSource::ImmutableTree {
            tree: ObjectDescriptor::new(
                MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor".to_owned()).unwrap(),
                ObjectDigest::from_bytes([10; 32]),
                11,
            ),
        };
        assert!(
            SourceRealizationBindingV1::new(
                [1; 16],
                2,
                descriptor(3, 4),
                immutable.clone(),
                MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
                Some([5; 16])
            )
            .is_err()
        );
        assert!(
            SourceRealizationBindingV1::new(
                [1; 16],
                2,
                descriptor(3, 4),
                immutable,
                MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
                Some([5; 16])
            )
            .is_err()
        );
        assert!(
            SourceRealizationBindingV1::new(
                [1; 16],
                2,
                descriptor(3, 4),
                live_binding().source,
                MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn constructor_and_canonical_decoder_enforce_identical_source_roles() {
        let immutable = ViewSource::ImmutableTree {
            tree: ObjectDescriptor::new(
                MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor".to_owned()).unwrap(),
                ObjectDigest::from_bytes([10; 32]),
                11,
            ),
        };
        let binding = SourceRealizationBindingV1::new(
            [1; 16],
            2,
            descriptor(3, 4),
            immutable,
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
            None,
        )
        .unwrap();
        assert_eq!(
            SourceRealizationBindingV1::from_canonical_bytes(&binding.canonical_bytes()).unwrap(),
            binding
        );
        assert_eq!(
            SourceRealizationBindingV1::from_canonical_bytes(&live_binding().canonical_bytes())
                .unwrap(),
            live_binding()
        );

        let invalid = ViewSource::ImmutableTree {
            tree: descriptor(10, 11),
        };
        assert!(matches!(
            SourceRealizationBindingV1::new(
                [1; 16],
                2,
                descriptor(3, 4),
                invalid.clone(),
                MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
                None,
            ),
            Err(SourceBindingError::InvalidSourceDescriptor(_))
        ));
        assert!(
            decode_view_source(&encode_view_source(&invalid), DecodeLimits::default()).is_err()
        );
        let forged = SourceRealizationBindingV1 {
            source_view_id: [1; 16],
            source_view_revision: 2,
            view_descriptor: descriptor(3, 4),
            source: invalid,
            consistency: MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
            source_incarnation_id: None,
        };
        assert!(
            SourceRealizationBindingV1::from_canonical_bytes(&forged.canonical_bytes()).is_err()
        );
    }

    #[test]
    fn constructor_and_canonical_decoder_reject_every_live_source_sentinel() {
        let invalid_sources = [
            ViewSource::LiveExport {
                owner_sandbox: SandboxId::from_bytes([0; 16]),
                export: ExportId::from_bytes([6; 16]),
                source_generation: Revision::new(7),
            },
            ViewSource::LiveExport {
                owner_sandbox: SandboxId::from_bytes([5; 16]),
                export: ExportId::from_bytes([0; 16]),
                source_generation: Revision::new(7),
            },
            ViewSource::LiveExport {
                owner_sandbox: SandboxId::from_bytes([5; 16]),
                export: ExportId::from_bytes([6; 16]),
                source_generation: Revision::new(0),
            },
        ];

        for source in invalid_sources {
            assert!(matches!(
                SourceRealizationBindingV1::new(
                    [1; 16],
                    2,
                    descriptor(3, 4),
                    source.clone(),
                    MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
                    Some([8; 16]),
                ),
                Err(SourceBindingError::IncompatibleSource)
            ));
            let forged = SourceRealizationBindingV1 {
                source_view_id: [1; 16],
                source_view_revision: 2,
                view_descriptor: descriptor(3, 4),
                source,
                consistency: MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
                source_incarnation_id: Some([8; 16]),
            };
            assert!(
                SourceRealizationBindingV1::from_canonical_bytes(&forged.canonical_bytes())
                    .is_err()
            );
        }
    }
}

//! Canonical codec for generation-fenced attachment desired state.
//!
//! ```text
//! attachment = [
//!   version, attachment-id, desired-generation,
//!   consumer-sandbox, consumer-incarnation, namespace-generation,
//!   source-view, source-revision, source-incarnation-or-null,
//!   view-descriptor, destination-slot, consistency, mutation,
//!   mount-attributes, lease
//! ]
//! attachment-v2 = [attachment-v1 fields with version=2, presentation]
//! mount-attributes = [version, ro, noexec, nosuid, nodev, noatime, recursive]
//! lease = [version, lease-id, issued-seconds, expires-seconds]
//! ```

use crate::model::{
    AttachmentConsistency, AttachmentIntent, AttachmentLease, AttachmentPresentation,
    MountAttributes,
};
use crate::{
    AttachmentId, AttachmentSlotId, DescriptorRole, DesiredGeneration, IncarnationId, LeaseId,
    NamespaceGeneration, Revision, SandboxId, ViewId,
};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{decode_descriptor_for_role, encode_descriptor, exact_bytes, semantics};
use super::view::{decode_view_mutation, view_mutation_code};

/// Encodes one native attachment intent in its exact canonical v1 form.
///
/// # Errors
///
/// Rejects a FUSE intent rather than dropping its presentation selection.
pub fn encode_attachment_intent_v1(
    intent: &AttachmentIntent,
) -> Result<Vec<u8>, CanonicalCborError> {
    if intent.presentation() != AttachmentPresentation::Native {
        return Err(CanonicalCborError::InvalidSemantics {
            object: "attachment intent v1",
            message: "FUSE presentation requires attachment intent v2".to_owned(),
        });
    }
    Ok(encode_attachment_intent(intent, 1))
}

/// Encodes one explicitly selected attachment intent in canonical v2 form.
#[must_use]
pub fn encode_attachment_intent_v2(intent: &AttachmentIntent) -> Vec<u8> {
    encode_attachment_intent(intent, 2)
}

fn encode_attachment_intent(intent: &AttachmentIntent, version: u64) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(if version == 1 { 15 } else { 16 });
    encoder.unsigned(version);
    encoder.bytes(intent.id().as_bytes());
    encoder.unsigned(intent.desired_generation().get());

    let (consumer_sandbox, consumer_incarnation) = intent.consumer();
    encoder.bytes(consumer_sandbox.as_bytes());
    encoder.bytes(consumer_incarnation.as_bytes());
    encoder.unsigned(intent.expected_namespace_generation().get());

    let (source_view, source_revision) = intent.source_view();
    encoder.bytes(source_view.as_bytes());
    encoder.unsigned(source_revision.get());
    match intent.source_incarnation() {
        Some(incarnation) => encoder.bytes(incarnation.as_bytes()),
        None => encoder.null(),
    }

    encode_descriptor(&mut encoder, intent.view());
    encoder.bytes(intent.destination_slot().as_bytes());
    encoder.unsigned(consistency_code(intent.consistency()));
    encoder.unsigned(view_mutation_code(intent.mutation()));
    encode_mount_attributes(&mut encoder, intent.mount_attributes());
    encode_lease(&mut encoder, intent.lease());
    if version == 2 {
        encoder.unsigned(presentation_code(intent.presentation()));
    }
    encoder.finish()
}

/// Decodes one exact canonical v1 attachment intent.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for noncanonical CBOR, a wrong schema,
/// unknown enum values, invalid descriptor roles, sentinel identities, unsafe
/// mount attributes, or inconsistent live-source semantics.
pub fn decode_attachment_intent_v1(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<AttachmentIntent, CanonicalCborError> {
    decode_attachment_intent(bytes, limits, 1)
}

/// Decodes one explicit canonical v2 attachment intent.
///
/// # Errors
///
/// Rejects the errors documented by [`decode_attachment_intent_v1`] and an
/// unknown presentation value or incompatible FUSE source semantics.
pub fn decode_attachment_intent_v2(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<AttachmentIntent, CanonicalCborError> {
    decode_attachment_intent(bytes, limits, 2)
}

fn decode_attachment_intent(
    bytes: &[u8],
    limits: DecodeLimits,
    version: u64,
) -> Result<AttachmentIntent, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(if version == 1 { 15 } else { 16 })?;
    decoder.exact("attachment intent version", version)?;
    let id = AttachmentId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let desired_generation = DesiredGeneration::new(decoder.unsigned()?);
    let consumer_sandbox = SandboxId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let consumer_incarnation = IncarnationId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let expected_namespace_generation = NamespaceGeneration::new(decoder.unsigned()?);
    let source_view = ViewId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let source_view_revision = Revision::new(decoder.unsigned()?);
    let source_incarnation =
        decoder.nullable(|decoder| exact_bytes(decoder, 16).map(IncarnationId::from_bytes))?;
    let view = decode_descriptor_for_role(&mut decoder, DescriptorRole::FilesystemViewRevision)?;
    let destination_slot = AttachmentSlotId::from_bytes(exact_bytes(&mut decoder, 16)?);
    let consistency = decode_consistency(&mut decoder)?;
    let mutation = decode_view_mutation(&mut decoder)?;
    let mount_attributes = decode_mount_attributes(&mut decoder)?;
    let lease = decode_lease(&mut decoder)?;
    let presentation = if version == 1 {
        AttachmentPresentation::Native
    } else {
        decode_presentation(&mut decoder)?
    };
    decoder.finish()?;

    AttachmentIntent::new_with_presentation(
        id,
        desired_generation,
        consumer_sandbox,
        consumer_incarnation,
        expected_namespace_generation,
        source_view,
        source_view_revision,
        source_incarnation,
        view,
        destination_slot,
        consistency,
        mutation,
        mount_attributes,
        lease,
        presentation,
    )
    .map_err(|error| semantics("attachment intent", error))
}

const fn presentation_code(presentation: AttachmentPresentation) -> u64 {
    match presentation {
        AttachmentPresentation::Native => 0,
        AttachmentPresentation::Fuse => 1,
    }
}

fn decode_presentation(
    decoder: &mut Decoder<'_>,
) -> Result<AttachmentPresentation, CanonicalCborError> {
    match decoder.closed("attachment presentation", 1)? {
        0 => Ok(AttachmentPresentation::Native),
        1 => Ok(AttachmentPresentation::Fuse),
        _ => Err(CanonicalCborError::InvalidSemantics {
            object: "attachment presentation",
            message: "closed registry returned an unknown value".to_owned(),
        }),
    }
}

const fn consistency_code(consistency: AttachmentConsistency) -> u64 {
    match consistency {
        AttachmentConsistency::ImmutableRevision => 0,
        AttachmentConsistency::LocalLive => 1,
        AttachmentConsistency::TransactionalService => 2,
        AttachmentConsistency::BestEffortReplica => 3,
    }
}

fn decode_consistency(
    decoder: &mut Decoder<'_>,
) -> Result<AttachmentConsistency, CanonicalCborError> {
    Ok(match decoder.closed("attachment consistency", 3)? {
        0 => AttachmentConsistency::ImmutableRevision,
        1 => AttachmentConsistency::LocalLive,
        2 => AttachmentConsistency::TransactionalService,
        3 => AttachmentConsistency::BestEffortReplica,
        _ => unreachable!("closed attachment consistency"),
    })
}

fn encode_mount_attributes(encoder: &mut Encoder, attributes: MountAttributes) {
    encoder.array(7);
    encoder.unsigned(1);
    encoder.boolean(attributes.read_only());
    encoder.boolean(attributes.no_exec());
    encoder.boolean(attributes.no_suid());
    encoder.boolean(attributes.no_dev());
    encoder.boolean(attributes.no_atime());
    encoder.boolean(attributes.recursive());
}

fn decode_mount_attributes(
    decoder: &mut Decoder<'_>,
) -> Result<MountAttributes, CanonicalCborError> {
    decoder.array(7)?;
    decoder.exact("attachment mount attributes version", 1)?;
    Ok(MountAttributes::new(
        decoder.boolean()?,
        decoder.boolean()?,
        decoder.boolean()?,
        decoder.boolean()?,
        decoder.boolean()?,
        decoder.boolean()?,
    ))
}

fn encode_lease(encoder: &mut Encoder, lease: AttachmentLease) {
    encoder.array(4);
    encoder.unsigned(1);
    encoder.bytes(lease.id().as_bytes());
    encoder.signed(lease.issued_seconds());
    encoder.signed(lease.expires_seconds());
}

fn decode_lease(decoder: &mut Decoder<'_>) -> Result<AttachmentLease, CanonicalCborError> {
    decoder.array(4)?;
    decoder.exact("attachment lease version", 1)?;
    let id = LeaseId::from_bytes(exact_bytes(decoder, 16)?);
    let issued_seconds = decoder.signed()?;
    let expires_seconds = decoder.signed()?;
    AttachmentLease::new(id, issued_seconds, expires_seconds)
        .map_err(|error| semantics("attachment lease", error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ViewMutation;
    use crate::{MediaType, ObjectDescriptor, ObjectDigest};

    fn descriptor() -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new("application/vnd.aos.sandbox.view.v1+cbor")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([9; 32]),
            42,
        )
    }

    fn intent() -> AttachmentIntent {
        AttachmentIntent::new(
            AttachmentId::from_bytes([1; 16]),
            DesiredGeneration::new(2),
            SandboxId::from_bytes([3; 16]),
            IncarnationId::from_bytes([4; 16]),
            NamespaceGeneration::new(5),
            ViewId::from_bytes([6; 16]),
            Revision::new(7),
            Some(IncarnationId::from_bytes([8; 16])),
            descriptor(),
            AttachmentSlotId::from_bytes([10; 16]),
            AttachmentConsistency::LocalLive,
            ViewMutation::ReadOnly,
            MountAttributes::new(true, true, true, true, true, false),
            AttachmentLease::new(LeaseId::from_bytes([11; 16]), -12, 13)
                .unwrap_or_else(|error| panic!("test lease failed: {error}")),
        )
        .unwrap_or_else(|error| panic!("test attachment failed: {error}"))
    }

    fn fuse_intent() -> AttachmentIntent {
        AttachmentIntent::new_with_presentation(
            AttachmentId::from_bytes([1; 16]),
            DesiredGeneration::new(2),
            SandboxId::from_bytes([3; 16]),
            IncarnationId::from_bytes([4; 16]),
            NamespaceGeneration::new(5),
            ViewId::from_bytes([6; 16]),
            Revision::new(7),
            None,
            descriptor(),
            AttachmentSlotId::from_bytes([10; 16]),
            AttachmentConsistency::ImmutableRevision,
            ViewMutation::ReadOnly,
            MountAttributes::new(true, true, true, true, true, false),
            AttachmentLease::new(LeaseId::from_bytes([11; 16]), -12, 13).unwrap(),
            AttachmentPresentation::Fuse,
        )
        .unwrap()
    }

    #[test]
    fn attachment_intent_matches_golden_and_round_trips() {
        let intent = intent();
        let encoded = encode_attachment_intent_v1(&intent).unwrap();

        assert_eq!(
            hex::encode(&encoded),
            "8f01500101010101010101010101010101010102500303030303030303030303030303030350040404040404040404040404040404040550060606060606060606060606060606060750080808080808080808080808080808088478286170706c69636174696f6e2f766e642e616f732e73616e64626f782e766965772e76312b63626f720158200909090909090909090909090909090909090909090909090909090909090909182a500a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a01008701f5f5f5f5f5f48401500b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b2b0d"
        );
        assert_eq!(
            decode_attachment_intent_v1(&encoded, DecodeLimits::default()),
            Ok(intent)
        );
    }

    #[test]
    fn decoder_rejects_unknown_consistency() {
        let mut encoded = encode_attachment_intent_v1(&intent()).unwrap();
        let destination = [0x50_u8].into_iter().chain([10_u8; 16]).collect::<Vec<_>>();
        let destination_offset = encoded
            .windows(destination.len())
            .position(|window| window == destination)
            .unwrap_or_else(|| panic!("test destination bytes missing"));
        encoded[destination_offset + destination.len()] = 4;

        assert!(matches!(
            decode_attachment_intent_v1(&encoded, DecodeLimits::default()),
            Err(CanonicalCborError::UnknownRegistryValue {
                registry: "attachment consistency",
                ..
            })
        ));
    }

    #[test]
    fn decoder_rechecks_mount_safety_semantics() {
        let mut encoded = encode_attachment_intent_v1(&intent()).unwrap();
        let attributes = [0x87, 0x01, 0xf5, 0xf5, 0xf5, 0xf5, 0xf5, 0xf4];
        let attributes_offset = encoded
            .windows(attributes.len())
            .position(|window| window == attributes)
            .unwrap_or_else(|| panic!("test attribute bytes missing"));
        encoded[attributes_offset + 4] = 0xf4;

        assert!(matches!(
            decode_attachment_intent_v1(&encoded, DecodeLimits::default()),
            Err(CanonicalCborError::InvalidSemantics {
                object: "attachment intent",
                ..
            })
        ));
    }

    #[test]
    fn fuse_requires_v2_and_v2_rejects_unknown_presentation() {
        let intent = fuse_intent();
        assert!(matches!(
            encode_attachment_intent_v1(&intent),
            Err(CanonicalCborError::InvalidSemantics { .. })
        ));

        let mut encoded = encode_attachment_intent_v2(&intent);
        assert_eq!(&encoded[..2], &[0x90, 0x02]);
        assert_eq!(encoded.last(), Some(&1));
        assert_eq!(
            decode_attachment_intent_v2(&encoded, DecodeLimits::default()),
            Ok(intent)
        );
        assert!(decode_attachment_intent_v1(&encoded, DecodeLimits::default()).is_err());

        *encoded.last_mut().unwrap() = 2;
        assert!(matches!(
            decode_attachment_intent_v2(&encoded, DecodeLimits::default()),
            Err(CanonicalCborError::UnknownRegistryValue {
                registry: "attachment presentation",
                ..
            })
        ));
    }

    #[test]
    fn native_v2_is_explicit_and_v1_decoder_cannot_accept_it() {
        let intent = intent();
        let encoded = encode_attachment_intent_v2(&intent);
        assert_eq!(encoded.last(), Some(&0));
        assert_eq!(
            decode_attachment_intent_v2(&encoded, DecodeLimits::default()),
            Ok(intent)
        );
        assert!(decode_attachment_intent_v1(&encoded, DecodeLimits::default()).is_err());
    }
}

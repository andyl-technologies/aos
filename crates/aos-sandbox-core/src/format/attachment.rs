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
//! mount-attributes = [version, ro, noexec, nosuid, nodev, noatime, recursive]
//! lease = [version, lease-id, issued-seconds, expires-seconds]
//! ```

use crate::model::{AttachmentConsistency, AttachmentIntent, AttachmentLease, MountAttributes};
use crate::{
    AttachmentId, AttachmentSlotId, DescriptorRole, DesiredGeneration, IncarnationId, LeaseId,
    NamespaceGeneration, Revision, SandboxId, ViewId,
};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{decode_descriptor_for_role, encode_descriptor, exact_bytes, semantics};
use super::view::{decode_view_mutation, view_mutation_code};

/// Encodes one attachment intent in its exact canonical v1 form.
#[must_use]
pub fn encode_attachment_intent_v1(intent: &AttachmentIntent) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(15);
    encoder.unsigned(1);
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
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(15)?;
    decoder.exact("attachment intent version", 1)?;
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
    decoder.finish()?;

    AttachmentIntent::new(
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
    )
    .map_err(|error| semantics("attachment intent", error))
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

    #[test]
    fn attachment_intent_matches_golden_and_round_trips() {
        let intent = intent();
        let encoded = encode_attachment_intent_v1(&intent);

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
        let mut encoded = encode_attachment_intent_v1(&intent());
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
        let mut encoded = encode_attachment_intent_v1(&intent());
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
}

//! Verifies that downstream clients can construct portable spec publications.

#![allow(clippy::unwrap_used)]

use std::num::NonZeroU32;

use aos_sandbox::SandboxSpecPublicationV1;
use aos_sandbox_core::model::{
    IdentityProfile, NetworkKind, NetworkProfile, ResourceProfile, SandboxSpec,
    UnmappableIdentityPolicy,
};
use aos_sandbox_core::{
    AttachmentSlotId, FeatureRef, MediaType, ObjectDescriptor, ObjectDigest, OperationId,
    PortableMediaType,
};

fn descriptor(kind: PortableMediaType, byte: u8) -> ObjectDescriptor {
    ObjectDescriptor::new(
        MediaType::new(kind.as_str().to_owned()).unwrap(),
        ObjectDigest::from_bytes([byte; 32]),
        1,
    )
}

#[test]
fn downstream_code_can_publish_a_canonical_sandbox_specification() {
    let slot_id = AttachmentSlotId::from_bytes([3; 16]);
    let spec = SandboxSpec::new(
        FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).unwrap(),
        IdentityProfile::PrivateUserns {
            id_range_size: NonZeroU32::new(65_536).unwrap(),
            unmappable_policy: UnmappableIdentityPolicy::Reject,
            required_features: Vec::new(),
        },
        ResourceProfile::new(Vec::new()).unwrap(),
        descriptor(PortableMediaType::Environment, 1),
        descriptor(PortableMediaType::View, 2),
        vec![slot_id],
        NetworkProfile::new(NetworkKind::Isolated, Vec::new(), Vec::new()).unwrap(),
        Vec::new(),
    )
    .unwrap();

    let publication = SandboxSpecPublicationV1::new(
        spec,
        OperationId::from_bytes([4; 16]),
        ObjectDigest::from_bytes([5; 32]),
    )
    .unwrap();
    assert_eq!(
        publication.descriptor().media_type().as_str(),
        PortableMediaType::SandboxSpec.as_str()
    );
    assert_ne!(publication.descriptor().encoded_size(), 0);
}

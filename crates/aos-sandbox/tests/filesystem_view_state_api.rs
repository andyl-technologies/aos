//! Verifies that downstream controller clients can construct view mutations.

#![allow(clippy::unwrap_used)]

use aos_sandbox::{FilesystemViewRevisionMutationV1, FilesystemViewRevisionPresenceV1};
use aos_sandbox_core::model::{
    CacheDomain, CacheDomainKind, View, ViewConsistency, ViewMutation, ViewSource,
};
use aos_sandbox_core::{
    CacheDomainId, DecodeLimits, FeatureRef, MediaType, ObjectDescriptor, ObjectDigest,
    OperationId, Revision, ViewId, decode_view, encode_view,
};

#[test]
fn downstream_code_can_name_filesystem_view_revision_inputs() {
    let view = View::new(
        ViewSource::ImmutableTree {
            tree: ObjectDescriptor::new(
                MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor").unwrap(),
                ObjectDigest::from_bytes([1; 32]),
                1,
            ),
        },
        Vec::new(),
        ViewConsistency::Immutable,
        ViewMutation::ReadOnly,
        FeatureRef::new("aos.sandbox.identity.posix32", 1, 0).unwrap(),
        CacheDomain::new(CacheDomainKind::Private, CacheDomainId::from_bytes([2; 16])),
        Vec::new(),
    )
    .unwrap();
    let encoded = encode_view(&view);
    assert_eq!(
        decode_view(&encoded, DecodeLimits::default()).unwrap(),
        view
    );

    let mutation = FilesystemViewRevisionMutationV1::new(
        FilesystemViewRevisionPresenceV1::Available,
        ViewId::from_bytes([3; 16]),
        Revision::new(1),
        view,
        OperationId::from_bytes([4; 16]),
        ObjectDigest::from_bytes([5; 32]),
        None,
    )
    .unwrap();
    assert_eq!(mutation.revision(), Revision::new(1));
}

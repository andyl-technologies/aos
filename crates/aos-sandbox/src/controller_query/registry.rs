//! Closed base-v1 portable descriptor, feature, and timestamp validation.

use aos_proto::aos::sandbox::v1::{Feature, ObjectDescriptor, Timestamp};

use super::resource::{InvalidPublicResource, MAXIMUM_CONDITION_FEATURES};

pub(crate) fn checked_timestamp(value: &Timestamp) -> Result<(i64, u32), InvalidPublicResource> {
    const MINIMUM_PROTO_SECONDS: i64 = -62_135_596_800;
    const MAXIMUM_PROTO_SECONDS: i64 = 253_402_300_799;

    if !(MINIMUM_PROTO_SECONDS..=MAXIMUM_PROTO_SECONDS).contains(&value.seconds)
        || value.nanoseconds >= 1_000_000_000
    {
        Err(InvalidPublicResource::InvalidScalar)
    } else {
        Ok((value.seconds, value.nanoseconds))
    }
}

pub(crate) fn validate_descriptor(value: &ObjectDescriptor) -> Result<(), InvalidPublicResource> {
    const MEDIA_TYPES: &[&str] = &[
        "application/vnd.aos.sandbox.content.v1",
        "application/vnd.aos.sandbox.policy.v1+cbor",
        "application/vnd.aos.sandbox.tree.v1+cbor",
        "application/vnd.aos.sandbox.directory.v1+cbor",
        "application/vnd.aos.sandbox.delta.v1+cbor",
        "application/vnd.aos.sandbox.view.v1+cbor",
        "application/vnd.aos.sandbox.environment.v1+cbor",
        "application/vnd.aos.sandbox.optimization.v1+cbor",
        "application/vnd.aos.sandbox.spec.v1+cbor",
        "application/vnd.aos.sandbox.snapshot.v1+cbor",
        "application/vnd.aos.sandbox.trust-policy.v1+cbor",
        "application/vnd.aos.sandbox.signature.v1+cbor",
        "application/vnd.aos.sandbox.broker-authorization-plan.v1+cbor",
        "application/vnd.aos.sandbox.publisher-domain-plan.v1+cbor",
        "application/vnd.aos.sandbox.ownership-lease.v1+cbor",
        "application/vnd.aos.sandbox.ownership-transaction-receipt.v1",
    ];
    if !MEDIA_TYPES.contains(&value.media_type.as_str())
        || value.sha256.len() != 32
        || value.sha256.iter().all(|byte| *byte == 0)
        || value.encoded_size == 0
    {
        Err(InvalidPublicResource::InvalidCode)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_descriptor_media(
    value: &ObjectDescriptor,
    expected_media_type: &str,
) -> Result<(), InvalidPublicResource> {
    validate_descriptor(value)?;
    if value.media_type == expected_media_type {
        Ok(())
    } else {
        Err(InvalidPublicResource::InvalidCode)
    }
}

pub(crate) fn validate_features(features: &[Feature]) -> Result<(), InvalidPublicResource> {
    const FEATURES: &[&str] = &[
        "aos.sandbox.runtime.linux-systemd",
        "aos.sandbox.identity.posix32",
        "aos.sandbox.metadata.posix-acl",
        "aos.sandbox.symlink.absolute",
        "aos.sandbox.symlink.parent-escape",
        "aos.sandbox.enforcement.cgroup-v2",
        "aos.sandbox.enforcement.broker-ledger",
        "aos.sandbox.authorization.signed-plan-lease",
        "aos.sandbox.authentication.broker-session",
        "aos.sandbox.mount.source-acquisition",
        "aos.sandbox.enforcement.zfs-quota",
        "aos.sandbox.residency.node-bounded-shared",
        "aos.sandbox.residency.hard-isolated",
        "aos.sandbox.storage.portable",
        "aos.sandbox.storage.zfs-held-snapshot",
        "aos.sandbox.quiesce.guest",
        "aos.sandbox.quiesce.storage",
    ];
    if features.len() > MAXIMUM_CONDITION_FEATURES
        || features.iter().any(|feature| {
            feature.major != 1
                || feature.minor != 0
                || !FEATURES.contains(&feature.namespace.as_str())
        })
        || !features.windows(2).all(|pair| {
            (&pair[0].namespace, pair[0].major, pair[0].minor)
                < (&pair[1].namespace, pair[1].major, pair[1].minor)
        })
    {
        Err(InvalidPublicResource::CollectionNotCanonical)
    } else {
        Ok(())
    }
}

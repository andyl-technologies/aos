//! Closed base-v1 portable descriptor, feature, and timestamp validation.

use aos_proto::aos::sandbox::v1::{
    Feature, ObjectDescriptor, PublicFeatureDefinition, PublicFeatureRegistry, Timestamp,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::resource::{InvalidPublicResource, MAXIMUM_CONDITION_FEATURES};

/// Exact number of entries in the closed base-v1 semantic feature registry.
pub const BASE_V1_FEATURE_REGISTRY_ENTRIES: usize = 27;

/// Requires hard revocation before force-deletion cleanup begins.
pub const FORCE_DELETE_FEATURE_V1: &str = "aos.sandbox.deletion.force-revocation";
/// Requires a consumer-scoped cache pin or drain, never object-only retention.
pub const CACHE_CONSUMER_PIN_FEATURE_V1: &str = "aos.sandbox.cache.consumer-pin";
/// Requires holder proof before issuing an execution attachment route.
pub const EXECUTION_ATTACH_HOLDER_PROOF_FEATURE_V1: &str =
    "aos.sandbox.execution.attach-holder-proof";
/// Requires bounded detached execution-output capture.
pub const EXECUTION_DETACHED_CAPTURE_FEATURE_V1: &str = "aos.sandbox.execution.detached-capture";
/// Requires a live pseudo-terminal execution data path.
pub const EXECUTION_PTY_FEATURE_V1: &str = "aos.sandbox.execution.pty";
/// Requires explicit sandbox-resident shell interpretation.
pub const EXECUTION_SANDBOX_SHELL_FEATURE_V1: &str = "aos.sandbox.execution.sandbox-shell";
/// Requires live non-terminal execution stream semantics.
pub const EXECUTION_STREAM_FEATURE_V1: &str = "aos.sandbox.execution.stream";
/// Requires server-enforced execution lifetime termination.
pub const EXECUTION_TIMEOUT_FEATURE_V1: &str = "aos.sandbox.execution.timeout";
/// Requires an attachment whose execute permission is removed and verified.
pub const ATTACHMENT_NOEXEC_FEATURE_V1: &str = "aos.sandbox.attachment.noexec";
/// Requires an exact current project-version fence for snapshot fork publication.
pub const SNAPSHOT_PROJECT_VERSION_FENCE_FEATURE_V1: &str =
    "aos.sandbox.snapshot.project-version-fence";

/// Identifies one closed public policy-plan reason.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PublicPolicyReasonCodeV1 {
    /// The requested semantics were accepted unchanged.
    RequestAccepted,
    /// Policy attenuated requested semantics.
    RequestAttenuated,
    /// A semantic feature is required.
    RequiredFeature,
    /// Current resource state conflicts with the request.
    ResourceConflict,
    /// Current policy conflicts with the request.
    PolicyConflict,
    /// A parent constraint changed the effective plan.
    ParentConstraint,
    /// No conforming backend is currently available.
    BackendUnavailable,
}

impl PublicPolicyReasonCodeV1 {
    /// Decodes the established protobuf enum value.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPublicResource::InvalidCode`] for unspecified or unknown values.
    pub const fn from_proto(value: i32) -> Result<Self, InvalidPublicResource> {
        match value {
            1 => Ok(Self::RequestAccepted),
            2 => Ok(Self::RequestAttenuated),
            3 => Ok(Self::RequiredFeature),
            4 => Ok(Self::ResourceConflict),
            5 => Ok(Self::PolicyConflict),
            6 => Ok(Self::ParentConstraint),
            7 => Ok(Self::BackendUnavailable),
            _ => Err(InvalidPublicResource::InvalidCode),
        }
    }

    /// Returns the established protobuf enum value.
    #[must_use]
    pub const fn to_proto(self) -> i32 {
        match self {
            Self::RequestAccepted => 1,
            Self::RequestAttenuated => 2,
            Self::RequiredFeature => 3,
            Self::ResourceConflict => 4,
            Self::PolicyConflict => 5,
            Self::ParentConstraint => 6,
            Self::BackendUnavailable => 7,
        }
    }

    /// Returns the stable legacy text projection retained for compatibility.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::RequestAccepted => "request-accepted",
            Self::RequestAttenuated => "request-attenuated",
            Self::RequiredFeature => "required-feature",
            Self::ResourceConflict => "resource-conflict",
            Self::PolicyConflict => "policy-conflict",
            Self::ParentConstraint => "parent-constraint",
            Self::BackendUnavailable => "backend-unavailable",
        }
    }
}

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
        "application/vnd.aos.sandbox.operator-recovery-evidence.v1",
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
    if features.len() > MAXIMUM_CONDITION_FEATURES
        || features
            .iter()
            .any(|feature| base_feature_registry_entry_v1(feature).is_none())
        || features.iter().any(|feature| {
            base_feature_incompatibilities_v1(&feature.namespace)
                .iter()
                .any(|incompatible| {
                    features
                        .iter()
                        .any(|candidate| candidate.namespace == *incompatible)
                })
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

fn base_feature_incompatibilities_v1(namespace: &str) -> &'static [&'static str] {
    match namespace {
        "aos.sandbox.residency.hard-isolated" => &["aos.sandbox.residency.node-bounded-shared"],
        "aos.sandbox.residency.node-bounded-shared" => &["aos.sandbox.residency.hard-isolated"],
        _ => &[],
    }
}

pub(crate) struct BaseFeatureRegistryEntryV1 {
    pub(crate) namespace: &'static str,
    pub(crate) safe_description: &'static str,
    fixture_role: &'static [u8],
    fixture_request: &'static [u8],
    fixture_observation: &'static [u8],
}

macro_rules! base_feature {
    (
        $namespace:literal,
        $description:literal,
        $role:literal,
        $request:literal,
        $observation:literal
    ) => {
        BaseFeatureRegistryEntryV1 {
            namespace: $namespace,
            safe_description: $description,
            fixture_role: $role,
            fixture_request: $request,
            fixture_observation: $observation,
        }
    };
}

const BASE_FEATURE_REGISTRY_V1: &[BaseFeatureRegistryEntryV1] = &[
    base_feature!(
        "aos.sandbox.attachment.noexec",
        "Verified noexec attachment",
        b"attach-view.mount-attributes",
        b"noexec=true",
        b"mount-attribute.noexec=verified"
    ),
    base_feature!(
        "aos.sandbox.authentication.broker-session",
        "Authenticated broker session",
        b"broker-session.authentication",
        b"holder-channel-binding=01010101010101010101010101010101",
        b"peer-identity=authenticated"
    ),
    base_feature!(
        "aos.sandbox.authorization.signed-plan-lease",
        "Signed plan lease authorization",
        b"broker-request.authorization",
        b"plan-generation=1;lease-generation=1",
        b"signature=verified;lease=current"
    ),
    base_feature!(
        "aos.sandbox.cache.consumer-pin",
        "Consumer-scoped cache pin and drain",
        b"cache-object.consumer-scope",
        b"view-id=nonzero;attachment-id=optional;object=exact",
        b"consumer=authorized;pin=renewable;unpin=complete-drain"
    ),
    base_feature!(
        "aos.sandbox.deletion.force-revocation",
        "Force deletion after hard revocation",
        b"delete-sandbox.revocation-order",
        b"force=true",
        b"consumer-cgroup=stopped;revocation=hard;cleanup=deferred"
    ),
    base_feature!(
        "aos.sandbox.enforcement.broker-ledger",
        "Broker ledger enforcement",
        b"resource-limit.enforcement",
        b"dimension=mount-count;value=1",
        b"reservation=committed;ledger=current"
    ),
    base_feature!(
        "aos.sandbox.enforcement.cgroup-v2",
        "Linux cgroup v2 enforcement",
        b"resource-limit.enforcement",
        b"dimension=memory-bytes;value=1048576",
        b"memory.max=1048576;readback=verified"
    ),
    base_feature!(
        "aos.sandbox.enforcement.zfs-quota",
        "ZFS quota enforcement",
        b"resource-limit.enforcement",
        b"dimension=storage-bytes;value=1048576",
        b"refquota=1048576;readback=verified"
    ),
    base_feature!(
        "aos.sandbox.execution.attach-holder-proof",
        "Holder proof for execution attachment",
        b"control-execution.attach-authority",
        b"action=attach;holder-key=present;proof=present",
        b"holder-proof=verified;certificate=holder-bound"
    ),
    base_feature!(
        "aos.sandbox.execution.detached-capture",
        "Bounded detached execution capture",
        b"create-execution.io-contract",
        b"io-mode=detached;capture-bytes=4096",
        b"live-stream=false;capture-limit=4096"
    ),
    base_feature!(
        "aos.sandbox.execution.pty",
        "Live pseudo-terminal execution",
        b"create-execution.io-contract",
        b"io-mode=pty;rows=24;columns=80",
        b"terminal=true;rows=24;columns=80"
    ),
    base_feature!(
        "aos.sandbox.execution.sandbox-shell",
        "Explicit sandbox-resident shell execution",
        b"create-execution.program",
        b"sandbox-shell=printf%20ok",
        b"interpreter=sandbox-resident;host-shell=false"
    ),
    base_feature!(
        "aos.sandbox.execution.stream",
        "Live non-terminal execution streams",
        b"create-execution.io-contract",
        b"io-mode=stream",
        b"terminal=false;live-stream=true"
    ),
    base_feature!(
        "aos.sandbox.execution.timeout",
        "Server-enforced execution timeout",
        b"create-execution.deadline",
        b"execution-timeout-nanoseconds=1000000000",
        b"deadline-termination=verified"
    ),
    base_feature!(
        "aos.sandbox.identity.posix32",
        "POSIX 32-bit identity",
        b"view.identity-presentation",
        b"uid=1000;gid=1000;unmappable=reject",
        b"presented-uid=1000;presented-gid=1000"
    ),
    base_feature!(
        "aos.sandbox.metadata.posix-acl",
        "POSIX ACL metadata",
        b"tree-entry.posix-acl",
        b"user::rw-;group::r--;mask::r--;other::---",
        b"mode=0640;mask-consistency=verified"
    ),
    base_feature!(
        "aos.sandbox.mount.source-acquisition",
        "Verified mount source acquisition",
        b"mount.source-custody",
        b"source-descriptor-sha256=0101010101010101010101010101010101010101010101010101010101010101",
        b"source-pin=verified;custody=current"
    ),
    base_feature!(
        "aos.sandbox.quiesce.guest",
        "Guest-coordinated quiescence",
        b"snapshot.quiesce-proof",
        b"mode=guest;transcript-sha256=0101010101010101010101010101010101010101010101010101010101010101",
        b"guest-acknowledgement=verified"
    ),
    base_feature!(
        "aos.sandbox.quiesce.storage",
        "Storage-coordinated quiescence",
        b"snapshot.quiesce-proof",
        b"mode=storage;transcript-sha256=0202020202020202020202020202020202020202020202020202020202020202",
        b"storage-flush=verified"
    ),
    base_feature!(
        "aos.sandbox.residency.hard-isolated",
        "Hard-isolated node residency",
        b"cache.residency-profile",
        b"profile=hard-isolated;limit-bytes=1048576",
        b"cache-identity=separate;bound=enforced"
    ),
    base_feature!(
        "aos.sandbox.residency.node-bounded-shared",
        "Node-bounded shared residency",
        b"cache.residency-profile",
        b"profile=node-bounded-shared;limit-bytes=1048576",
        b"node-bound=enforced;tenant-attribution=not-claimed"
    ),
    base_feature!(
        "aos.sandbox.runtime.linux-systemd",
        "Linux systemd runtime",
        b"sandbox-spec.runtime-profile",
        b"profile=linux-systemd;namespaces=user,pid,mount,uts,ipc,network",
        b"shared-kernel=true;private-namespaces=verified"
    ),
    base_feature!(
        "aos.sandbox.snapshot.project-version-fence",
        "Snapshot fork project version fence",
        b"fork-snapshot.project-version-fence",
        b"expected-project-resource-version=0102",
        b"project-resource-version=current;cas=verified"
    ),
    base_feature!(
        "aos.sandbox.storage.portable",
        "Portable sandbox storage",
        b"snapshot.storage-checkpoint",
        b"state=tree;backend-private-payload=absent",
        b"portable=true;dependencies=explicit"
    ),
    base_feature!(
        "aos.sandbox.storage.zfs-held-snapshot",
        "ZFS held-snapshot storage",
        b"snapshot.storage-checkpoint",
        b"state=tree;retention-receipt=present",
        b"zfs-hold=verified;dataset-name=absent"
    ),
    base_feature!(
        "aos.sandbox.symlink.absolute",
        "Absolute symlink semantics",
        b"tree-entry.symlink-target",
        b"target=/workspace/file",
        b"absolute-target=preserved;consumer-resolution=ordinary"
    ),
    base_feature!(
        "aos.sandbox.symlink.parent-escape",
        "Parent-escaping symlink semantics",
        b"tree-entry.symlink-target",
        b"target=../file",
        b"lexical-parent-escape=preserved;extra-access=false"
    ),
];

const _: [(); BASE_V1_FEATURE_REGISTRY_ENTRIES] = [(); BASE_FEATURE_REGISTRY_V1.len()];

/// Constructs one exact base-v1 semantic feature.
///
/// # Errors
///
/// Returns [`InvalidPublicResource::InvalidCode`] when `namespace` is
/// not a member of the closed public registry.
pub fn semantic_feature_v1(namespace: &str) -> Result<Feature, InvalidPublicResource> {
    let feature = Feature {
        namespace: namespace.to_owned(),
        major: 1,
        minor: 0,
        ..Default::default()
    };
    base_feature_registry_entry_v1(&feature)
        .map(|_| feature)
        .ok_or(InvalidPublicResource::InvalidCode)
}

/// Reports whether a canonical feature set contains every named base-v1 feature.
#[must_use]
pub fn contains_semantic_features_v1(features: &[Feature], required: &[&str]) -> bool {
    validate_features(features).is_ok()
        && required.iter().all(|namespace| {
            features
                .binary_search_by(|feature| feature.namespace.as_str().cmp(namespace))
                .is_ok()
        })
}

/// Constructs the complete canonical public feature registry.
#[must_use]
pub fn public_feature_registry_v1() -> PublicFeatureRegistry {
    let features = BASE_FEATURE_REGISTRY_V1
        .iter()
        .map(|entry| {
            let feature = Feature {
                namespace: entry.namespace.to_owned(),
                major: 1,
                minor: 0,
                ..Default::default()
            };
            PublicFeatureDefinition {
                feature: feature.clone().into(),
                safe_description: entry.safe_description.to_owned(),
                conformance_fixture_digest: feature_fixture_digest_v1(entry).to_vec(),
                ..Default::default()
            }
        })
        .collect();
    let mut registry = PublicFeatureRegistry {
        schema_version: 1,
        features,
        registry_digest: Vec::new(),
        ..Default::default()
    };
    registry.registry_digest = public_feature_registry_digest_v1(&registry).to_vec();
    registry
}

pub(crate) fn base_feature_registry_entry_v1(
    feature: &Feature,
) -> Option<&'static BaseFeatureRegistryEntryV1> {
    if feature.major != 1 || feature.minor != 0 {
        return None;
    }
    BASE_FEATURE_REGISTRY_V1
        .binary_search_by(|entry| entry.namespace.cmp(feature.namespace.as_str()))
        .ok()
        .map(|index| &BASE_FEATURE_REGISTRY_V1[index])
}

/// Resolves a registry-owned digest from checked-in base-v1 fixture bytes.
pub(crate) fn feature_conformance_digest_v1(feature: &Feature) -> Option<[u8; 32]> {
    let entry = base_feature_registry_entry_v1(feature)?;
    Some(feature_fixture_digest_v1(entry))
}

/// Returns the canonical binary semantic fixture registered for one feature.
///
/// The fixture is an `AOSFCF01` frame containing the canonical protobuf
/// encoding of the exact feature triple followed by length-prefixed role,
/// request, and verified-observation records.
#[must_use]
pub fn canonical_feature_fixture_v1(feature: &Feature) -> Option<Vec<u8>> {
    base_feature_registry_entry_v1(feature).map(canonical_feature_fixture_entry_v1)
}

fn feature_fixture_digest_v1(entry: &BaseFeatureRegistryEntryV1) -> [u8; 32] {
    Sha256::digest(canonical_feature_fixture_entry_v1(entry)).into()
}

fn canonical_feature_fixture_entry_v1(entry: &BaseFeatureRegistryEntryV1) -> Vec<u8> {
    let feature = Feature {
        namespace: entry.namespace.to_owned(),
        major: 1,
        minor: 0,
        ..Default::default()
    }
    .encode_to_vec();
    let mut fixture = Vec::new();
    fixture.extend_from_slice(b"AOSFCF01");
    append_fixture_field(&mut fixture, &feature);
    append_fixture_field(&mut fixture, entry.fixture_role);
    append_fixture_field(&mut fixture, entry.fixture_request);
    append_fixture_field(&mut fixture, entry.fixture_observation);
    fixture
}

fn append_fixture_field(fixture: &mut Vec<u8>, field: &[u8]) {
    let length = field.len() as u64;
    fixture.extend_from_slice(&length.to_be_bytes());
    fixture.extend_from_slice(field);
}

/// Computes the canonical registry commitment with its digest field excluded.
pub(crate) fn public_feature_registry_digest_v1(registry: &PublicFeatureRegistry) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.public-feature-registry.v1\0");
    digest.update(registry.schema_version.to_be_bytes());
    digest.update((registry.features.len() as u64).to_be_bytes());
    for definition in &registry.features {
        if let Some(feature) = definition.feature.as_option() {
            hash_bytes(&mut digest, feature.namespace.as_bytes());
            digest.update(feature.major.to_be_bytes());
            digest.update(feature.minor.to_be_bytes());
        } else {
            hash_bytes(&mut digest, &[]);
            digest.update(0_u32.to_be_bytes());
            digest.update(0_u32.to_be_bytes());
        }
        hash_bytes(&mut digest, definition.safe_description.as_bytes());
        hash_bytes(&mut digest, &definition.conformance_fixture_digest);
    }
    digest.finalize().into()
}

fn hash_bytes(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

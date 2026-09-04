//! Closed portable-format, feature, descriptor-role, and protocol registries.
//!
//! Registry decisions are authority decisions. The v1 tables are compiled into
//! readers and writers, use exact identifiers, and reject unknown required
//! semantics instead of treating an unfamiliar value as advisory metadata.

use crate::model::SignaturePurpose;
use crate::{FeatureRef, ObjectDescriptor};

/// Reports a closed-registry or compatibility violation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RegistryError {
    /// A required feature is not implemented by the base-v1 registry.
    #[error("unknown required feature {namespace} version {major}.{minor}")]
    UnknownRequiredFeature {
        /// Ownership-namespaced feature identifier.
        namespace: String,
        /// Required semantic major version.
        major: u32,
        /// Required semantic minor version.
        minor: u32,
    },
    /// A descriptor uses an unregistered portable media type.
    #[error("unregistered portable media type {media_type}")]
    UnknownMediaType {
        /// Exact media type found in the descriptor.
        media_type: String,
    },
    /// A registered object kind appears in a field with another semantic role.
    #[error("media type {media_type} is invalid for descriptor role {role:?}")]
    DescriptorRoleMismatch {
        /// Field role being validated.
        role: DescriptorRole,
        /// Exact mismatched media type.
        media_type: String,
    },
    /// A signature purpose cannot authenticate the subject object kind.
    #[error("signature purpose {purpose:?} cannot authenticate {media_type}")]
    SignatureSubjectMismatch {
        /// Claimed signature purpose.
        purpose: SignaturePurpose,
        /// Exact subject media type.
        media_type: String,
    },
    /// A peer uses an incompatible protocol major or newer semantic minor.
    #[error(
        "unsupported {protocol:?} protocol version {offered_major}.{offered_minor}; local version is {local_major}.{local_minor}"
    )]
    IncompatibleProtocol {
        /// Independently versioned protocol domain.
        protocol: ProtocolId,
        /// Offered major version.
        offered_major: u16,
        /// Offered minor version.
        offered_minor: u16,
        /// Local major version.
        local_major: u16,
        /// Local maximum semantic minor version.
        local_minor: u16,
    },
}

/// Names every registered portable v1 stored-object media type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PortableMediaType {
    /// Immutable raw file or auxiliary content bytes.
    Content,
    /// One canonical directory object.
    Directory,
    /// One complete portable tree root.
    Tree,
    /// One canonical final-tree delta.
    Delta,
    /// One immutable filesystem view revision.
    View,
    /// One immutable project environment.
    Environment,
    /// Advisory optimization data.
    Optimization,
    /// One portable sandbox specification.
    SandboxSpec,
    /// One normalized effective policy.
    Policy,
    /// One execution-independent snapshot manifest.
    Snapshot,
    /// One exact trust-policy generation.
    TrustPolicy,
    /// One detached signature envelope.
    Signature,
    /// One controller-signed audience-specific local broker plan.
    BrokerAuthorizationPlan,
    /// One ownership-authority-signed node lease.
    OwnershipLease,
    /// One ownership-authority-signed claim-to-lease transaction receipt.
    OwnershipTransactionReceipt,
}

impl PortableMediaType {
    /// Returns the exact registered media type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Content => "application/vnd.aos.sandbox.content.v1",
            Self::Directory => "application/vnd.aos.sandbox.directory.v1+cbor",
            Self::Tree => "application/vnd.aos.sandbox.tree.v1+cbor",
            Self::Delta => "application/vnd.aos.sandbox.delta.v1+cbor",
            Self::View => "application/vnd.aos.sandbox.view.v1+cbor",
            Self::Environment => "application/vnd.aos.sandbox.environment.v1+cbor",
            Self::Optimization => "application/vnd.aos.sandbox.optimization.v1+cbor",
            Self::SandboxSpec => "application/vnd.aos.sandbox.spec.v1+cbor",
            Self::Policy => "application/vnd.aos.sandbox.policy.v1+cbor",
            Self::Snapshot => "application/vnd.aos.sandbox.snapshot.v1+cbor",
            Self::TrustPolicy => "application/vnd.aos.sandbox.trust-policy.v1+cbor",
            Self::Signature => "application/vnd.aos.sandbox.signature.v1+cbor",
            Self::BrokerAuthorizationPlan => {
                "application/vnd.aos.sandbox.broker-authorization-plan.v1+cbor"
            }
            Self::OwnershipLease => "application/vnd.aos.sandbox.ownership-lease.v1+cbor",
            Self::OwnershipTransactionReceipt => {
                "application/vnd.aos.sandbox.ownership-transaction-receipt.v1"
            }
        }
    }

    /// Resolves one exact registered media type.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::UnknownMediaType`] for every unregistered or
    /// differently spelled value.
    pub fn parse(media_type: &str) -> Result<Self, RegistryError> {
        ALL_MEDIA_TYPES
            .iter()
            .copied()
            .find(|candidate| candidate.as_str() == media_type)
            .ok_or_else(|| RegistryError::UnknownMediaType {
                media_type: media_type.to_owned(),
            })
    }
}

const ALL_MEDIA_TYPES: [PortableMediaType; 15] = [
    PortableMediaType::Content,
    PortableMediaType::Directory,
    PortableMediaType::Tree,
    PortableMediaType::Delta,
    PortableMediaType::View,
    PortableMediaType::Environment,
    PortableMediaType::Optimization,
    PortableMediaType::SandboxSpec,
    PortableMediaType::Policy,
    PortableMediaType::Snapshot,
    PortableMediaType::TrustPolicy,
    PortableMediaType::Signature,
    PortableMediaType::BrokerAuthorizationPlan,
    PortableMediaType::OwnershipLease,
    PortableMediaType::OwnershipTransactionReceipt,
];

/// Identifies the semantic field in which a descriptor appears.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DescriptorRole {
    /// Directory entry child.
    DirectoryChild,
    /// Tree root directory.
    TreeRoot,
    /// Whole-file or sparse-extent content.
    FileContent,
    /// Delta base or result tree.
    DeltaTree,
    /// Object added to a delta result graph.
    DeltaAddedObject,
    /// Immutable view source.
    ImmutableViewSource,
    /// Project environment closure member.
    EnvironmentClosure,
    /// Sandbox specification environment.
    SandboxEnvironment,
    /// Sandbox specification root view.
    SandboxRootView,
    /// Generic immutable filesystem-view revision.
    FilesystemViewRevision,
    /// Tree selector target.
    TreeSelector,
    /// Policy optimization commitment.
    OptimizationCommitment,
    /// Snapshot sandbox specification.
    SnapshotSpec,
    /// Snapshot historical policy.
    SnapshotPolicy,
    /// Snapshot environment.
    SnapshotEnvironment,
    /// Snapshot private root.
    SnapshotPrivateRoot,
    /// Snapshot filesystem attachment.
    SnapshotAttachment,
    /// Portable storage checkpoint state.
    PortableStorageState,
    /// Immutable-view retention or dependency.
    ImmutableViewDependency,
    /// Environment retention or dependency.
    EnvironmentDependency,
    /// Content or closed portable-object retention.
    ContentRetention,
    /// Signature verification policy.
    SignatureVerificationPolicy,
}

/// Validates that a descriptor's registered media type is legal for its field.
///
/// # Errors
///
/// Returns [`RegistryError`] when the media type is unknown or the known object
/// kind cannot occupy `role`.
pub fn validate_descriptor_role(
    role: DescriptorRole,
    descriptor: &ObjectDescriptor,
) -> Result<PortableMediaType, RegistryError> {
    let kind = PortableMediaType::parse(descriptor.media_type().as_str())?;
    let allowed = match role {
        DescriptorRole::DirectoryChild | DescriptorRole::TreeRoot => {
            matches!(kind, PortableMediaType::Directory)
        }
        DescriptorRole::FileContent => matches!(kind, PortableMediaType::Content),
        DescriptorRole::DeltaTree | DescriptorRole::TreeSelector => {
            matches!(kind, PortableMediaType::Tree)
        }
        DescriptorRole::DeltaAddedObject => {
            matches!(
                kind,
                PortableMediaType::Directory | PortableMediaType::Content
            )
        }
        DescriptorRole::ContentRetention => true,
        DescriptorRole::ImmutableViewSource => matches!(kind, PortableMediaType::Tree),
        DescriptorRole::EnvironmentClosure => {
            matches!(kind, PortableMediaType::Content | PortableMediaType::Tree)
        }
        DescriptorRole::SandboxEnvironment
        | DescriptorRole::SnapshotEnvironment
        | DescriptorRole::EnvironmentDependency => {
            matches!(kind, PortableMediaType::Environment)
        }
        DescriptorRole::SandboxRootView
        | DescriptorRole::FilesystemViewRevision
        | DescriptorRole::SnapshotAttachment
        | DescriptorRole::ImmutableViewDependency => matches!(kind, PortableMediaType::View),
        DescriptorRole::OptimizationCommitment => {
            matches!(kind, PortableMediaType::Optimization)
        }
        DescriptorRole::SnapshotSpec => matches!(kind, PortableMediaType::SandboxSpec),
        DescriptorRole::SnapshotPolicy => matches!(kind, PortableMediaType::Policy),
        DescriptorRole::SnapshotPrivateRoot | DescriptorRole::PortableStorageState => {
            matches!(kind, PortableMediaType::Tree | PortableMediaType::Delta)
        }
        DescriptorRole::SignatureVerificationPolicy => {
            matches!(kind, PortableMediaType::TrustPolicy)
        }
    };
    if allowed {
        Ok(kind)
    } else {
        Err(RegistryError::DescriptorRoleMismatch {
            role,
            media_type: descriptor.media_type().as_str().to_owned(),
        })
    }
}

/// Validates every required feature against the exact base-v1 registry.
///
/// # Errors
///
/// Returns [`RegistryError::UnknownRequiredFeature`] for the first feature
/// whose exact namespace, major, and minor triple is not registered.
pub fn validate_required_features(features: &[FeatureRef]) -> Result<(), RegistryError> {
    for feature in features {
        let known = BASE_FEATURES.iter().any(|entry| {
            entry.namespace == feature.namespace()
                && entry.major == feature.major()
                && entry.minor == feature.minor()
        });
        if !known {
            return Err(RegistryError::UnknownRequiredFeature {
                namespace: feature.namespace().to_owned(),
                major: feature.major(),
                minor: feature.minor(),
            });
        }
    }
    Ok(())
}

/// Validates the closed signature-purpose-to-subject registry.
///
/// # Errors
///
/// Returns [`RegistryError`] when the subject media type is unknown or cannot
/// be authenticated under the claimed purpose.
pub fn validate_signature_subject(
    purpose: SignaturePurpose,
    subject: &ObjectDescriptor,
) -> Result<PortableMediaType, RegistryError> {
    let kind = PortableMediaType::parse(subject.media_type().as_str())?;
    let allowed = match purpose {
        SignaturePurpose::Policy => matches!(kind, PortableMediaType::Policy),
        SignaturePurpose::Tree => matches!(
            kind,
            PortableMediaType::Tree
                | PortableMediaType::Directory
                | PortableMediaType::Delta
                | PortableMediaType::View
                | PortableMediaType::Environment
        ),
        SignaturePurpose::Snapshot => {
            matches!(
                kind,
                PortableMediaType::Snapshot | PortableMediaType::SandboxSpec
            )
        }
        SignaturePurpose::Distribution => true,
        SignaturePurpose::BrokerAuthorization => {
            matches!(kind, PortableMediaType::BrokerAuthorizationPlan)
        }
        SignaturePurpose::OwnershipLease => matches!(
            kind,
            PortableMediaType::OwnershipLease | PortableMediaType::OwnershipTransactionReceipt
        ),
    };
    if allowed {
        Ok(kind)
    } else {
        Err(RegistryError::SignatureSubjectMismatch {
            purpose,
            media_type: subject.media_type().as_str().to_owned(),
        })
    }
}

#[derive(Clone, Copy)]
struct FeatureDefinition {
    namespace: &'static str,
    major: u32,
    minor: u32,
}

const BASE_FEATURES: [FeatureDefinition; 15] = [
    feature("aos.sandbox.runtime.linux-systemd"),
    feature("aos.sandbox.identity.posix32"),
    feature("aos.sandbox.metadata.posix-acl"),
    feature("aos.sandbox.symlink.absolute"),
    feature("aos.sandbox.symlink.parent-escape"),
    feature("aos.sandbox.enforcement.cgroup-v2"),
    feature("aos.sandbox.enforcement.broker-ledger"),
    feature("aos.sandbox.authorization.signed-plan-lease"),
    feature("aos.sandbox.enforcement.zfs-quota"),
    feature("aos.sandbox.residency.node-bounded-shared"),
    feature("aos.sandbox.residency.hard-isolated"),
    feature("aos.sandbox.storage.portable"),
    feature("aos.sandbox.storage.zfs-held-snapshot"),
    feature("aos.sandbox.quiesce.guest"),
    feature("aos.sandbox.quiesce.storage"),
];

const fn feature(namespace: &'static str) -> FeatureDefinition {
    FeatureDefinition {
        namespace,
        major: 1,
        minor: 0,
    }
}

/// Identifies one independently versioned sandbox protocol domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolId {
    /// Public `aos.sandbox.v1` API.
    PublicApi,
    /// Coordinator-to-node desired-state protocol.
    CoordinatorNode,
    /// Node-local root host broker.
    HostBroker,
    /// Node-local root storage broker.
    StorageBroker,
    /// Node-local root descriptor mount broker.
    MountBroker,
    /// Node-local root network broker.
    NetworkBroker,
    /// Transport-neutral exclusive ownership authority.
    OwnershipAuthority,
    /// Per-assignment ownership guardian.
    Guardian,
    /// Authenticated sandbox guest-agent channel.
    GuestAgent,
}

/// Stores an explicit protocol semantic major/minor version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    /// Constructs an explicit semantic protocol version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns the breaking semantic major version.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Returns the additive semantic minor version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

/// Negotiates one protocol independently from every other compatibility domain.
///
/// V1 peers must use the same major and cannot demand semantics newer than the
/// local maximum minor. Successful negotiation returns the offered version;
/// callers advertise only versions they have conformance-tested.
///
/// # Errors
///
/// Returns [`RegistryError::IncompatibleProtocol`] for a major mismatch or a
/// peer minor newer than the compiled registry.
pub fn negotiate_protocol(
    protocol: ProtocolId,
    offered: ProtocolVersion,
) -> Result<ProtocolVersion, RegistryError> {
    let local = protocol_version(protocol);
    if offered.major == local.major && offered.minor <= local.minor {
        Ok(offered)
    } else {
        Err(RegistryError::IncompatibleProtocol {
            protocol,
            offered_major: offered.major,
            offered_minor: offered.minor,
            local_major: local.major,
            local_minor: local.minor,
        })
    }
}

const fn protocol_version(protocol: ProtocolId) -> ProtocolVersion {
    match protocol {
        ProtocolId::HostBroker => ProtocolVersion::new(1, 2),
        ProtocolId::MountBroker | ProtocolId::StorageBroker | ProtocolId::NetworkBroker => {
            ProtocolVersion::new(1, 1)
        }
        ProtocolId::PublicApi
        | ProtocolId::CoordinatorNode
        | ProtocolId::OwnershipAuthority
        | ProtocolId::Guardian
        | ProtocolId::GuestAgent => ProtocolVersion::new(1, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MediaType, ObjectDigest};

    fn descriptor(kind: PortableMediaType) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(kind.as_str())
                .unwrap_or_else(|error| panic!("registered media type failed: {error}")),
            ObjectDigest::from_bytes([0; 32]),
            0,
        )
    }

    #[test]
    fn unknown_feature_versions_fail_closed() {
        let authorization = FeatureRef::new("aos.sandbox.authorization.signed-plan-lease", 1, 0)
            .unwrap_or_else(|error| panic!("test feature failed: {error}"));
        assert_eq!(validate_required_features(&[authorization]), Ok(()));

        let feature = FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 1)
            .unwrap_or_else(|error| panic!("test feature failed: {error}"));

        assert!(matches!(
            validate_required_features(&[feature]),
            Err(RegistryError::UnknownRequiredFeature { minor: 1, .. })
        ));
    }

    #[test]
    fn descriptor_roles_do_not_accept_digest_type_confusion() {
        assert!(matches!(
            validate_descriptor_role(
                DescriptorRole::SandboxEnvironment,
                &descriptor(PortableMediaType::View)
            ),
            Err(RegistryError::DescriptorRoleMismatch { .. })
        ));
    }

    #[test]
    fn signature_purpose_is_independent_from_valid_signature_bytes() {
        assert!(matches!(
            validate_signature_subject(
                SignaturePurpose::Policy,
                &descriptor(PortableMediaType::Snapshot)
            ),
            Err(RegistryError::SignatureSubjectMismatch { .. })
        ));
        assert_eq!(
            validate_signature_subject(
                SignaturePurpose::OwnershipLease,
                &descriptor(PortableMediaType::OwnershipLease)
            ),
            Ok(PortableMediaType::OwnershipLease)
        );
        assert_eq!(
            validate_signature_subject(
                SignaturePurpose::OwnershipLease,
                &descriptor(PortableMediaType::OwnershipTransactionReceipt)
            ),
            Ok(PortableMediaType::OwnershipTransactionReceipt)
        );
        assert!(matches!(
            validate_signature_subject(
                SignaturePurpose::OwnershipLease,
                &descriptor(PortableMediaType::BrokerAuthorizationPlan)
            ),
            Err(RegistryError::SignatureSubjectMismatch { .. })
        ));
    }

    #[test]
    fn protocol_domains_negotiate_independently_and_fail_newer_versions() {
        assert_eq!(
            negotiate_protocol(ProtocolId::MountBroker, ProtocolVersion::new(1, 0)),
            Ok(ProtocolVersion::new(1, 0))
        );
        assert_eq!(
            negotiate_protocol(ProtocolId::MountBroker, ProtocolVersion::new(1, 1)),
            Ok(ProtocolVersion::new(1, 1))
        );
        assert_eq!(
            negotiate_protocol(ProtocolId::HostBroker, ProtocolVersion::new(1, 1)),
            Ok(ProtocolVersion::new(1, 1))
        );
        assert_eq!(
            negotiate_protocol(ProtocolId::HostBroker, ProtocolVersion::new(1, 2)),
            Ok(ProtocolVersion::new(1, 2))
        );
        assert_eq!(
            negotiate_protocol(ProtocolId::OwnershipAuthority, ProtocolVersion::new(1, 0)),
            Ok(ProtocolVersion::new(1, 0))
        );
        assert!(matches!(
            negotiate_protocol(ProtocolId::MountBroker, ProtocolVersion::new(1, 2)),
            Err(RegistryError::IncompatibleProtocol { .. })
        ));
        assert!(matches!(
            negotiate_protocol(ProtocolId::PublicApi, ProtocolVersion::new(2, 0)),
            Err(RegistryError::IncompatibleProtocol { .. })
        ));
        assert!(matches!(
            negotiate_protocol(ProtocolId::CoordinatorNode, ProtocolVersion::new(1, 1)),
            Err(RegistryError::IncompatibleProtocol { .. })
        ));
        assert!(matches!(
            negotiate_protocol(ProtocolId::OwnershipAuthority, ProtocolVersion::new(1, 1)),
            Err(RegistryError::IncompatibleProtocol { .. })
        ));
    }
}

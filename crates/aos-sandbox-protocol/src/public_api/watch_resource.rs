//! Full-resource envelopes for public watch snapshot bootstraps.
//!
//! Snapshot chunks retain complete, versioned resources rather than references
//! that would require an unpinned follow-up `Get`. Construction delegates to
//! each resource's strict checker, including condition correlation and the
//! execution credential-redaction boundary.

use aos_proto::aos::sandbox::v1::{
    Attachment, Capability, Execution, FilesystemView, NodeCapabilities, Operation, Sandbox,
    Snapshot,
};

use super::model::ClientStateItem;
use super::observation::{
    CheckedOperationObservationV1, CheckedSandboxObservationV1, InvalidObservationMetadata,
};
use super::portable_resource::{
    CheckedAttachmentResourceV1, CheckedCapabilityResourceV1, CheckedExecutionResourceV1,
    CheckedFilesystemViewResourceV1, CheckedNodeCapabilitiesV1, CheckedSnapshotResourceV1,
};
use super::resource::InvalidPublicResource;

/// Reports a malformed full resource supplied in a watch snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidWatchSnapshotResource {
    /// Sandbox or operation observation metadata is not fully correlated.
    #[error(transparent)]
    InvalidObservation(#[from] InvalidObservationMetadata),
    /// A resource fails its complete public-resource validation.
    #[error(transparent)]
    InvalidResource(#[from] InvalidPublicResource),
}

/// Identifies the closed set of resources that may appear in a watch snapshot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WatchSnapshotResourceTypeV1 {
    /// A sandbox status resource.
    Sandbox,
    /// A durable operation status resource.
    Operation,
    /// An execution status resource.
    Execution,
    /// A filesystem-view status resource.
    FilesystemView,
    /// An attachment status resource.
    Attachment,
    /// A snapshot status resource.
    Snapshot,
    /// A non-secret capability lifetime resource.
    Capability,
    /// A public node-capability inventory sample.
    NodeCapabilities,
}

/// Borrows the redacted protobuf projection of one checked snapshot resource.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PublicWatchSnapshotResourceRefV1<'a> {
    /// A sandbox status resource.
    Sandbox(&'a Sandbox),
    /// A durable operation status resource.
    Operation(&'a Operation),
    /// An execution status resource with holder credentials removed.
    Execution(&'a Execution),
    /// A filesystem-view status resource.
    FilesystemView(&'a FilesystemView),
    /// An attachment status resource.
    Attachment(&'a Attachment),
    /// A snapshot status resource.
    Snapshot(&'a Snapshot),
    /// A non-secret capability lifetime resource.
    Capability(&'a Capability),
    /// A public node-capability inventory sample.
    NodeCapabilities(&'a NodeCapabilities),
}

/// Stores one complete, deeply checked resource from a watch snapshot.
///
/// Every variant retains the exact resource version received under the chunk's
/// watermark. Resource-specific construction validates identifiers, versions,
/// conditions, generations, observation sequences, and nested status. The
/// execution variant exposes only its credential-redacted public projection.
#[derive(Clone, Debug, PartialEq)]
pub enum CheckedWatchSnapshotResourceV1 {
    /// A sandbox with complete additive controller observation metadata.
    Sandbox(CheckedSandboxObservationV1),
    /// An operation with complete additive condition metadata.
    Operation(CheckedOperationObservationV1),
    /// An execution with checked condition and placement correlation.
    Execution(CheckedExecutionResourceV1),
    /// A filesystem view with checked condition correlation.
    FilesystemView(CheckedFilesystemViewResourceV1),
    /// An attachment with checked condition and placement correlation.
    Attachment(CheckedAttachmentResourceV1),
    /// A snapshot with checked condition correlation.
    Snapshot(CheckedSnapshotResourceV1),
    /// A checked non-secret capability lifetime.
    Capability(CheckedCapabilityResourceV1),
    /// A checked node-capability inventory sample.
    NodeCapabilities(CheckedNodeCapabilitiesV1),
}

impl CheckedWatchSnapshotResourceV1 {
    /// Returns the resource's closed snapshot-envelope type.
    #[must_use]
    pub const fn resource_type(&self) -> WatchSnapshotResourceTypeV1 {
        match self {
            Self::Sandbox(_) => WatchSnapshotResourceTypeV1::Sandbox,
            Self::Operation(_) => WatchSnapshotResourceTypeV1::Operation,
            Self::Execution(_) => WatchSnapshotResourceTypeV1::Execution,
            Self::FilesystemView(_) => WatchSnapshotResourceTypeV1::FilesystemView,
            Self::Attachment(_) => WatchSnapshotResourceTypeV1::Attachment,
            Self::Snapshot(_) => WatchSnapshotResourceTypeV1::Snapshot,
            Self::Capability(_) => WatchSnapshotResourceTypeV1::Capability,
            Self::NodeCapabilities(_) => WatchSnapshotResourceTypeV1::NodeCapabilities,
        }
    }

    /// Returns the exact checked logical resource identifier.
    #[must_use]
    pub fn resource_id(&self) -> &[u8] {
        match self.public_resource() {
            PublicWatchSnapshotResourceRefV1::Sandbox(resource) => &resource.sandbox_id,
            PublicWatchSnapshotResourceRefV1::Operation(resource) => &resource.operation_id,
            PublicWatchSnapshotResourceRefV1::Execution(resource) => &resource.execution_id,
            PublicWatchSnapshotResourceRefV1::FilesystemView(resource) => &resource.view_id,
            PublicWatchSnapshotResourceRefV1::Attachment(resource) => &resource.attachment_id,
            PublicWatchSnapshotResourceRefV1::Snapshot(resource) => &resource.snapshot_id,
            PublicWatchSnapshotResourceRefV1::Capability(resource) => &resource.capability_id,
            PublicWatchSnapshotResourceRefV1::NodeCapabilities(resource) => &resource.node_id,
        }
    }

    /// Returns the exact opaque resource version pinned by the snapshot.
    #[must_use]
    pub fn resource_version(&self) -> &[u8] {
        match self.public_resource() {
            PublicWatchSnapshotResourceRefV1::Sandbox(resource) => &resource.resource_version,
            PublicWatchSnapshotResourceRefV1::Operation(resource) => &resource.resource_version,
            PublicWatchSnapshotResourceRefV1::Execution(resource) => &resource.resource_version,
            PublicWatchSnapshotResourceRefV1::FilesystemView(resource) => {
                &resource.resource_version
            }
            PublicWatchSnapshotResourceRefV1::Attachment(resource) => &resource.resource_version,
            PublicWatchSnapshotResourceRefV1::Snapshot(resource) => &resource.resource_version,
            PublicWatchSnapshotResourceRefV1::Capability(resource) => &resource.resource_version,
            PublicWatchSnapshotResourceRefV1::NodeCapabilities(resource) => {
                &resource.resource_version
            }
        }
    }

    /// Returns the complete public protobuf resource after required redaction.
    #[must_use]
    pub const fn public_resource(&self) -> PublicWatchSnapshotResourceRefV1<'_> {
        match self {
            Self::Sandbox(resource) => {
                PublicWatchSnapshotResourceRefV1::Sandbox(resource.resource().as_proto())
            }
            Self::Operation(resource) => {
                PublicWatchSnapshotResourceRefV1::Operation(resource.resource().as_proto())
            }
            Self::Execution(resource) => {
                PublicWatchSnapshotResourceRefV1::Execution(resource.as_proto())
            }
            Self::FilesystemView(resource) => {
                PublicWatchSnapshotResourceRefV1::FilesystemView(resource.as_proto())
            }
            Self::Attachment(resource) => {
                PublicWatchSnapshotResourceRefV1::Attachment(resource.as_proto())
            }
            Self::Snapshot(resource) => {
                PublicWatchSnapshotResourceRefV1::Snapshot(resource.as_proto())
            }
            Self::Capability(resource) => {
                PublicWatchSnapshotResourceRefV1::Capability(resource.as_proto())
            }
            Self::NodeCapabilities(resource) => {
                PublicWatchSnapshotResourceRefV1::NodeCapabilities(resource.as_proto())
            }
        }
    }
}

impl TryFrom<Sandbox> for CheckedWatchSnapshotResourceV1 {
    type Error = InvalidWatchSnapshotResource;

    fn try_from(value: Sandbox) -> Result<Self, Self::Error> {
        CheckedSandboxObservationV1::try_from(value)
            .map(Self::Sandbox)
            .map_err(Into::into)
    }
}

impl TryFrom<Operation> for CheckedWatchSnapshotResourceV1 {
    type Error = InvalidWatchSnapshotResource;

    fn try_from(value: Operation) -> Result<Self, Self::Error> {
        CheckedOperationObservationV1::try_from(value)
            .map(Self::Operation)
            .map_err(Into::into)
    }
}

macro_rules! checked_snapshot_conversion {
    ($wire:ty, $checked:ty, $variant:ident) => {
        impl TryFrom<$wire> for CheckedWatchSnapshotResourceV1 {
            type Error = InvalidWatchSnapshotResource;

            fn try_from(value: $wire) -> Result<Self, Self::Error> {
                <$checked>::try_from(value)
                    .map(Self::$variant)
                    .map_err(Into::into)
            }
        }
    };
}

checked_snapshot_conversion!(Execution, CheckedExecutionResourceV1, Execution);
checked_snapshot_conversion!(
    FilesystemView,
    CheckedFilesystemViewResourceV1,
    FilesystemView
);
checked_snapshot_conversion!(Attachment, CheckedAttachmentResourceV1, Attachment);
checked_snapshot_conversion!(Snapshot, CheckedSnapshotResourceV1, Snapshot);
checked_snapshot_conversion!(Capability, CheckedCapabilityResourceV1, Capability);
checked_snapshot_conversion!(
    NodeCapabilities,
    CheckedNodeCapabilitiesV1,
    NodeCapabilities
);

impl super::client_state_sealed::Sealed for CheckedWatchSnapshotResourceV1 {}

impl ClientStateItem for CheckedWatchSnapshotResourceV1 {
    fn encoded_byte_cost(&self) -> usize {
        match self {
            Self::Sandbox(resource) => resource.resource().encoded_byte_cost(),
            Self::Operation(resource) => resource.resource().encoded_byte_cost(),
            Self::Execution(resource) => resource.encoded_byte_cost(),
            Self::FilesystemView(resource) => resource.encoded_byte_cost(),
            Self::Attachment(resource) => resource.encoded_byte_cost(),
            Self::Snapshot(resource) => resource.encoded_byte_cost(),
            Self::Capability(resource) => resource.encoded_byte_cost(),
            Self::NodeCapabilities(resource) => resource.encoded_byte_cost(),
        }
    }
}

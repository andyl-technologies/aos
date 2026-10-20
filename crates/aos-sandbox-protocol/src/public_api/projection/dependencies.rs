//! Extracts explicit logical dependencies from the canonical public models.
//!
//! Both the protected Delete planner and the all-transaction tombstone guard
//! consume this one projection. It uses recorded logical identities only.
//! Source-owned View backing, Snapshot content and physical inventories remain
//! independent inputs; no descriptor digest is converted to a resource ID.

use aos_sandbox_core::{ExecutionId, ResourceId, SandboxId, SnapshotId, ViewId};

use super::{PublicProjectionError, PublicProjectionRecordV1, PublicProjectionResourceV1};
use crate::domain_ledger::lifecycle_model::{LifecycleDependencyEdgeV1, LifecycleResourceV1};

/// Retains the explicit owner and at most two dependencies of one checked row.
///
/// This is passive DATA. It authenticates neither the supplied projection nor
/// completeness, currentness, a deletion closure or a native disposition.
#[derive(Clone, Copy, Debug)]
pub struct PublicProjectionDependenciesDataV2 {
    resource: Option<LifecycleResourceV1>,
    edges: [Option<LifecycleDependencyEdgeV1>; 2],
}

impl PublicProjectionDependenciesDataV2 {
    /// Returns the row's explicit logical identity, if it represents a resource.
    #[must_use]
    pub const fn resource_v2(self) -> Option<LifecycleResourceV1> {
        self.resource
    }

    /// Borrows every explicit dependency in its fixed schema order.
    pub fn edges_v2(&self) -> impl Iterator<Item = LifecycleDependencyEdgeV1> + '_ {
        self.edges.iter().flatten().copied()
    }
}

/// Extracts the complete explicit ID relations of one canonical public row.
///
/// The row's existing codec validates all other model fields. Cache-status
/// rows own no logical lifecycle resource. A View's Source owner is not stored
/// in this public schema and must be joined through its genuine Source row.
///
/// # Errors
/// Refuses zero or non-16-byte resource identities and self dependencies.
pub fn projection_dependencies_data_v2(
    record: &PublicProjectionRecordV1,
) -> Result<PublicProjectionDependenciesDataV2, PublicProjectionError> {
    use LifecycleResourceV1 as Resource;
    use PublicProjectionResourceV1 as Projection;

    let (resource, dependencies) = match record.resource() {
        Projection::Sandbox(value) => {
            let parent = if value.parent_sandbox_id.is_empty() {
                None
            } else {
                Some(Resource::Sandbox(SandboxId::from_bytes(identity(&value.parent_sandbox_id)?)))
            };
            (Resource::Sandbox(SandboxId::from_bytes(identity(&value.sandbox_id)?)), [parent, None])
        }
        Projection::Execution(value) => (
            Resource::Execution(ExecutionId::from_bytes(identity(&value.execution_id)?)),
            [Some(Resource::Sandbox(SandboxId::from_bytes(identity(&value.sandbox_id)?))), None],
        ),
        Projection::FilesystemView(value) => (
            Resource::View(ViewId::from_bytes(identity(&value.view_id)?)), [None, None],
        ),
        Projection::Attachment(value) => (
            Resource::Attachment(ResourceId::from_bytes(identity(&value.attachment_id)?)),
            [Some(Resource::Sandbox(SandboxId::from_bytes(identity(&value.sandbox_id)?))),
                Some(Resource::View(ViewId::from_bytes(identity(&value.source_view_id)?)))],
        ),
        Projection::Snapshot(value) => (
            Resource::Snapshot(SnapshotId::from_bytes(identity(&value.snapshot_id)?)),
            [Some(Resource::Sandbox(SandboxId::from_bytes(identity(&value.source_sandbox_id)?))), None],
        ),
        Projection::Capability(value) => {
            let sandbox = if value.sandbox_id.is_empty() {
                None
            } else {
                Some(Resource::Sandbox(SandboxId::from_bytes(identity(&value.sandbox_id)?)))
            };
            (Resource::Capability(ResourceId::from_bytes(identity(&value.capability_id)?)), [sandbox, None])
        }
        Projection::ProjectCacheStatus { .. } | Projection::SandboxCacheStatus { .. } => {
            return Ok(PublicProjectionDependenciesDataV2 { resource: None, edges: [None, None] });
        }
    };
    let mut edges = [None, None];
    for (index, dependency) in dependencies.into_iter().enumerate() {
        if let Some(dependency) = dependency {
            edges[index] = Some(LifecycleDependencyEdgeV1::new(resource, dependency)
                .map_err(|_| PublicProjectionError::InvalidIdentity)?);
        }
    }
    Ok(PublicProjectionDependenciesDataV2 { resource: Some(resource), edges })
}

/// Derives the explicit same-assignment Execution-to-Attachment relation.
///
/// This compares complete current C models only. It proves no kernel consumer
/// absence or terminal state. All phases remain conservative consumers until a
/// real native stop/disposal and protected retirement remove their relation.
///
/// # Errors
/// Refuses incorrect model kinds, malformed identities or cross-project rows.
pub fn assignment_attachment_consumer_data_v2(
    execution: &PublicProjectionRecordV1,
    attachment: &PublicProjectionRecordV1,
) -> Result<Option<LifecycleDependencyEdgeV1>, PublicProjectionError> {
    let (PublicProjectionResourceV1::Execution(execution_model),
        PublicProjectionResourceV1::Attachment(attachment_model)) =
        (execution.resource(), attachment.resource())
    else { return Err(PublicProjectionError::InvalidIdentity); };
    if execution.project() != attachment.project() { return Ok(None); }
    if execution_model.sandbox_id != attachment_model.sandbox_id
        || execution_model.assignment_epoch == 0
        || execution_model.assignment_epoch != attachment_model.assignment_epoch
    { return Ok(None); }
    LifecycleDependencyEdgeV1::new(
        LifecycleResourceV1::Execution(ExecutionId::from_bytes(identity(&execution_model.execution_id)?)),
        LifecycleResourceV1::Attachment(ResourceId::from_bytes(identity(&attachment_model.attachment_id)?)),
    ).map(Some).map_err(|_| PublicProjectionError::InvalidIdentity)
}

// The same public codec can be reached by the all-transaction barrier on a
// hostile proposed row. Bound its actual enum, nested protobuf carriers and
// canonical reencoding before that validator runs. Only one row is decoded at
// a time; the caller separately retains its complete original map/transaction.
/// Returns bytes for one reached public-projection dependency decode.
#[must_use]
pub fn projection_dependencies_receiving_bytes_v2(encoded: usize) -> Option<usize> {
    let width = std::mem::size_of::<PublicProjectionResourceV1>();
    let protobuf = aos_sandbox_broker_session_protocol::receiving_geometry::protobuf_carriers_v1(
        u64::try_from(encoded).ok()?, u64::try_from(width).ok()?,
    ).ok()?;
    let fixed = std::mem::size_of::<PublicProjectionRecordV1>().checked_mul(3)?
        .checked_add(std::mem::size_of::<PublicProjectionDependenciesDataV2>().checked_mul(3)?)?;
    fixed.checked_add(usize::try_from(protobuf).ok()?)
}

fn identity(bytes: &[u8]) -> Result<[u8; 16], PublicProjectionError> {
    let identity: [u8; 16] = bytes.try_into().map_err(|_| PublicProjectionError::InvalidIdentity)?;
    if identity == [0; 16] {
        Err(PublicProjectionError::InvalidIdentity)
    } else {
        Ok(identity)
    }
}

/// Compares every canonical public descriptor field with a complete Core value.
///
/// This comparison neither verifies content bytes nor grants a disclosure,
/// native read, role, admission or immutable-file proof.
#[must_use]
pub fn object_descriptor_matches_data_v2(
    proto: &aos_proto::aos::sandbox::v1::ObjectDescriptor,
    descriptor: &aos_sandbox_core::ObjectDescriptor,
) -> bool {
    proto.media_type == descriptor.media_type().as_str()
        && proto.sha256.as_slice() == descriptor.digest().as_bytes()
        && proto.encoded_size == descriptor.encoded_size()
}

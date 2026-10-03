//! Acquisition-only join between a public Cache consumer and View source proof.

use aos_filesystem_view_core::ValidatedViewSourceObject;
use aos_sandbox_core::{
    AttachmentId, IncarnationId, NodeId, ObjectDescriptor, ProjectId, SandboxId, ViewId,
};

use super::{CacheAuthorityScopeV1, CachePinId, CachePinV1, PhysicalPartitionId, PinError};
use crate::production_operation_compiler::RecheckedCacheConsumerV1;

/// Reports a mismatch before protected Cache pin authority may be requested.
#[derive(Debug, thiserror::Error)]
pub enum PublicLogicalPinAcquisitionErrorV1 {
    /// Release-only consumers cannot acquire a new physical obligation.
    #[error("cache consumer has no acquisition fence")]
    ReleaseOnly,
    /// The source proof does not cover this exact current View and object.
    #[error("cache object is not bound to the current consumer View source")]
    SourceMismatch,
    /// The selected physical partition is not on the local controller node.
    #[error("cache partition belongs to another node")]
    PartitionNodeMismatch,
    /// The attached runtime does not match the local node and consumer shape.
    #[error("cache attachment runtime is not current on the local node")]
    RuntimeMismatch,
}

/// Retains the checked source proof and consumer for one local logical pin.
///
/// This is not protected Cache authority. The caller must still select a
/// committed catalog entry in `partition`, acquire a current PinAcquire record,
/// and recheck the desired consumer before the protected pin transaction.
pub struct ValidatedPublicLogicalPinAcquisitionV1<'a, 'projection, 'index, 'bytes> {
    consumer: &'a RecheckedCacheConsumerV1,
    source: &'a ValidatedViewSourceObject<'projection, 'index, 'bytes>,
    partition: PhysicalPartitionId,
}

impl<'a, 'projection, 'index, 'bytes>
    ValidatedPublicLogicalPinAcquisitionV1<'a, 'projection, 'index, 'bytes>
{
    /// Joins exact source membership, current consumer identity, and local partition.
    ///
    /// # Errors
    ///
    /// Rejects a release-only consumer, stale or substituted source proof,
    /// a remote partition, or a mismatched attached runtime.
    pub fn new(
        consumer: &'a RecheckedCacheConsumerV1,
        source: &'a ValidatedViewSourceObject<'projection, 'index, 'bytes>,
        partition: PhysicalPartitionId,
        controller_node: NodeId,
    ) -> Result<Self, PublicLogicalPinAcquisitionErrorV1> {
        let fence = consumer
            .acquisition_fence()
            .ok_or(PublicLogicalPinAcquisitionErrorV1::ReleaseOnly)?;
        let (source_view, source_generation) = source.view_identity();
        if source.object() != consumer.object()
            || source_view != consumer.view()
            || source_generation.get() != fence.view_generation()
            || source.view_descriptor() != fence.view_revision()
        {
            return Err(PublicLogicalPinAcquisitionErrorV1::SourceMismatch);
        }
        if partition.node().as_bytes() != controller_node.as_bytes() {
            return Err(PublicLogicalPinAcquisitionErrorV1::PartitionNodeMismatch);
        }
        match (consumer.attachment(), fence.runtime()) {
            (None, None) => {}
            (Some(_), Some(runtime)) if runtime.node() == controller_node => {}
            _ => return Err(PublicLogicalPinAcquisitionErrorV1::RuntimeMismatch),
        }

        Ok(Self {
            consumer,
            source,
            partition,
        })
    }

    /// Returns the exact object present in the authenticated source.
    #[must_use]
    pub fn object(&self) -> &ObjectDescriptor {
        self.source.object()
    }

    /// Returns the project charged for this logical dependency.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.consumer.project()
    }

    /// Returns the consuming View identity.
    #[must_use]
    pub const fn view(&self) -> ViewId {
        self.consumer.view()
    }

    /// Returns the consuming attachment, when one was named.
    #[must_use]
    pub const fn attachment(&self) -> Option<AttachmentId> {
        self.consumer.attachment()
    }

    /// Returns the selected local physical partition.
    #[must_use]
    pub const fn partition(&self) -> PhysicalPartitionId {
        self.partition
    }

    /// Borrows the exact rechecked public consumer for commit-time validation.
    #[must_use]
    pub const fn consumer(&self) -> &RecheckedCacheConsumerV1 {
        self.consumer
    }

    pub(crate) fn runtime_fields(&self) -> (Option<SandboxId>, Option<IncarnationId>, u64) {
        let runtime = self
            .consumer
            .acquisition_fence()
            .and_then(|fence| fence.runtime());
        match runtime {
            Some(runtime) => (
                Some(runtime.sandbox()),
                Some(runtime.incarnation()),
                runtime.assignment_epoch(),
            ),
            None => (None, None, 0),
        }
    }

    pub(crate) fn authority_scope(
        &self,
        pin: CachePinId,
        valid_until: u64,
    ) -> Result<CacheAuthorityScopeV1, PinError> {
        let (sandbox, incarnation, assignment_epoch) = self.runtime_fields();
        CachePinV1::logical_acquisition_scope(
            pin,
            self.partition,
            self.object(),
            self.project(),
            self.view(),
            self.attachment(),
            sandbox,
            incarnation,
            assignment_epoch,
            valid_until,
        )
    }
}

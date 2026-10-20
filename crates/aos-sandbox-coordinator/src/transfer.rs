//! Owns remote transfer request selection over genuine native endpoint loans.
//!
//! No endpoint, current map, grant or positive receipt can be adopted from DATA.
//! The actual local owners retain trust, clocks, artifacts, admission, native
//! publication and outcome-unknown recovery. This module sequences the existing
//! resume/chunk/dependency requests without adding a listener, worker or retry.

use aos_sandbox::local_inventory::ProtectedMultiNodeAuthorityOwnerV1;
use aos_sandbox::local_inventory::protocol::AuthenticatedNodeSessionV1;
use aos_sandbox::local_inventory::remote::{
    ProtectedMultiNodeUpdateErrorV1, ProtectedOutboundNodeRequestV1,
    ProtectedSnapshotDestinationAuthorityOwnerV1,
};
use aos_sandbox_core::{
    InvalidSnapshotTransfer, MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES, NodeRequestBodyV1,
    SnapshotDependencyRangeV1, SnapshotTransferChunkRequestV1,
};

/// Borrows the distinct actual native endpoints for existing transfer planning.
pub struct SnapshotTransferCoordinatorV1<'source, 'destination> {
    source: &'source mut ProtectedMultiNodeAuthorityOwnerV1,
    destination: &'destination mut ProtectedSnapshotDestinationAuthorityOwnerV1,
}

impl<'source, 'destination> SnapshotTransferCoordinatorV1<'source, 'destination> {
    /// Borrows existing actual endpoint originals without opening or adopting any.
    #[must_use]
    pub fn new(
        source: &'source mut ProtectedMultiNodeAuthorityOwnerV1,
        destination: &'destination mut ProtectedSnapshotDestinationAuthorityOwnerV1,
    ) -> Self {
        Self {
            source,
            destination,
        }
    }

    /// Selects the existing begin-or-resume request from genuine native replay.
    ///
    /// # Errors
    ///
    /// Preserves the original replay, source admission, identity or native request cause.
    pub fn prepare_snapshot_resume_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let scope = self
            .destination
            .begin_snapshot_request_once_v1(self.source)?;
        let body = NodeRequestBodyV1::BeginSnapshotTransfer {
            manifest: Box::new(scope.manifest_v1().clone()),
            resume: Some(scope.resume_v1()),
        };
        scope.prepare_once_v1(session, body)
    }

    /// Selects exactly the next committed-manifest chunk from native readback.
    ///
    /// # Errors
    ///
    /// Preserves the original replay, admission, chunk bound or native issuer cause.
    pub fn prepare_next_snapshot_chunk_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let scope = self
            .destination
            .begin_snapshot_request_once_v1(self.source)?;
        let request = SnapshotTransferChunkRequestV1::new(
            scope.manifest_v1(),
            scope.resume_v1().next_chunk(),
        )?;
        scope.prepare_once_v1(session, NodeRequestBodyV1::FetchSnapshotChunk { request })
    }

    /// Selects the existing next bounded dependency range after chunks complete.
    ///
    /// # Errors
    ///
    /// Preserves the original replay, admission, completion, range or native issuer cause.
    pub fn prepare_next_snapshot_dependency_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let scope = self
            .destination
            .begin_snapshot_request_once_v1(self.source)?;
        if scope.resume_v1().next_chunk() as usize != scope.manifest_v1().chunks().len() {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let (dependency_index, projection) = scope
            .dependencies_v1()
            .iter()
            .enumerate()
            .find(|(_, dependency)| dependency.next_offset < dependency.descriptor.encoded_size())
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let remaining = projection
            .descriptor
            .encoded_size()
            .checked_sub(projection.next_offset)
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let length = u32::try_from(remaining.min(u64::from(MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES)))
            .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let request = SnapshotDependencyRangeV1::new(
            scope.manifest_v1(),
            u32::try_from(dependency_index)
                .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?,
            projection.next_offset,
            length,
        )?;
        scope.prepare_once_v1(
            session,
            NodeRequestBodyV1::FetchSnapshotDependency { request },
        )
    }
}

//! Finite genuine native loans for Coordinator drain/transfer request planning.
//!
//! These loans retain the actual source/destination owners and their current
//! protected readback. They cannot adopt a journal, map, timestamp or receipt.
//! Only exact existing request variants can reach the unchanged private native
//! outbound issuer; the Coordinator owns request selection and assembly.

use super::*;
use aos_sandbox_model::DurableDependencyProjectionV1;
use aos_sandbox_model::{
    DrainDirectiveV1, InvalidSnapshotTransfer, MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES,
    NodeRequestBodyV1, SnapshotTransferManifestV1, SnapshotTransferResumeV1,
};

/// Retains both genuine endpoints and their exact existing protected readback.
///
/// Private field order retires the source admission before destination DATA,
/// matching the original method-local reverse declaration order. Owner loans
/// outlive both; no native owner is replaced, adopted or disposed here.
pub struct ProtectedSnapshotRequestScopeV1<'source, 'destination> {
    admitted: ProtectedSnapshotSourceAdmissionV1,
    destination: SnapshotTransferJournalStateV1,
    source: &'source mut ProtectedMultiNodeAuthorityOwnerV1,
    _destination_owner: &'destination mut ProtectedSnapshotDestinationAuthorityOwnerV1,
}

impl ProtectedSnapshotDestinationAuthorityOwnerV1 {
    /// Borrows both actual endpoints after the original ordered native reads.
    ///
    /// # Errors
    ///
    /// Returns the original destination replay, source admission or exact
    /// source/destination manifest mismatch before request allocation.
    pub fn begin_snapshot_request_once_v1<'source, 'destination>(
        &'destination mut self,
        source: &'source mut ProtectedMultiNodeAuthorityOwnerV1,
    ) -> Result<
        ProtectedSnapshotRequestScopeV1<'source, 'destination>,
        ProtectedMultiNodeUpdateErrorV1,
    > {
        let destination = self.inner.current_snapshot_projection()?;
        let admitted = source.issue_current_snapshot_source_admission()?;
        if admitted.manifest != *destination.manifest() {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        Ok(ProtectedSnapshotRequestScopeV1 {
            admitted,
            destination,
            source,
            _destination_owner: self,
        })
    }
}

impl ProtectedSnapshotRequestScopeV1<'_, '_> {
    /// Borrows the exact native-read destination manifest DATA.
    #[must_use]
    pub fn manifest_v1(&self) -> &SnapshotTransferManifestV1 {
        self.destination.manifest()
    }

    /// Returns the existing destination's durable resume DATA.
    #[must_use]
    pub fn resume_v1(&self) -> SnapshotTransferResumeV1 {
        self.destination.resume()
    }

    /// Borrows exact current dependency-prefix DATA from native readback.
    #[must_use]
    pub fn dependencies_v1(&self) -> &[DurableDependencyProjectionV1] {
        self.destination.dependencies()
    }

    /// Consumes both real endpoint loans into the unchanged native request issuer.
    ///
    /// # Errors
    ///
    /// Returns the existing request/manifest/dependency refusal unless the
    /// supplied DATA selects precisely this readback's next old request, then
    /// preserves the original native session/currentness/encoding failure.
    pub fn prepare_once_v1(
        self,
        session: &AuthenticatedNodeSessionV1,
        body: NodeRequestBodyV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        // The private admission remains resident through the actual source
        // issuer. DATA equality alone never supplies source or destination authority.
        let _admitted = &self.admitted;
        let manifest = self.destination.manifest();
        let purpose: &'static [u8] = match &body {
            NodeRequestBodyV1::BeginSnapshotTransfer {
                manifest: proposed,
                resume,
            } => {
                if proposed.as_ref() != manifest || *resume != Some(self.destination.resume()) {
                    return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
                }
                b"snapshot-destination-resume"
            }
            NodeRequestBodyV1::FetchSnapshotChunk { request } => {
                let index = self.destination.resume().next_chunk();
                let chunk = manifest
                    .chunks()
                    .get(
                        usize::try_from(index)
                            .map_err(|_| InvalidSnapshotTransfer::ChunkIntegrityMismatch)?,
                    )
                    .filter(|chunk| chunk.index() == index)
                    .ok_or(InvalidSnapshotTransfer::ChunkIntegrityMismatch)?;
                if request.identity() != manifest.identity() || request.chunk() != *chunk {
                    return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch.into());
                }
                b"snapshot-destination-chunk"
            }
            NodeRequestBodyV1::FetchSnapshotDependency { request } => {
                if self.destination.resume().next_chunk() as usize != manifest.chunks().len() {
                    return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
                }
                let (_, current) = self
                    .destination
                    .dependencies()
                    .iter()
                    .enumerate()
                    .find(|(_, row)| row.next_offset < row.descriptor.encoded_size())
                    .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
                let remaining = current
                    .descriptor
                    .encoded_size()
                    .checked_sub(current.next_offset)
                    .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
                let length =
                    u32::try_from(remaining.min(u64::from(MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES)))
                        .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?;
                if request.identity() != manifest.identity()
                    || request.dependency() != &current.descriptor
                    || request.offset() != current.next_offset
                    || request.length() != length
                {
                    return Err(InvalidSnapshotTransfer::DependenciesNotCanonical.into());
                }
                b"snapshot-destination-dependency"
            }
            _ => return Err(InvalidMultiNodeProtocol::MethodMismatch.into()),
        };
        self.source
            .prepare_outbound_request(session, body, purpose)
            .map_err(Into::into)
    }
}

/// Retains actual current drain readback and the same mutable native owner.
pub struct ProtectedDrainRequestScopeV1<'owner> {
    state: DrainJournalStateV1,
    owner: &'owner mut ProtectedMultiNodeAuthorityOwnerV1,
}

impl ProtectedMultiNodeAuthorityOwnerV1 {
    /// Borrows the native drain state at the old request's exact read frontier.
    ///
    /// # Errors
    ///
    /// Returns the original replay failure or missing/wrong-domain HistoryGap.
    pub fn begin_drain_request_once_v1(
        &mut self,
    ) -> Result<ProtectedDrainRequestScopeV1<'_>, ProtectedMultiNodeUpdateErrorV1> {
        let state = match self.current_domain_projection(MultiNodeJournalDomainV1::Drain)? {
            Some(MultiNodeReducerStateV1::Drain(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        Ok(ProtectedDrainRequestScopeV1 { state, owner: self })
    }
}

impl ProtectedDrainRequestScopeV1<'_> {
    /// Borrows the exact current drain desired-state DATA.
    #[must_use]
    pub fn directive_v1(&self) -> &DrainDirectiveV1 {
        self.state.directive()
    }

    /// Consumes the actual owner loan for precisely the current drain request.
    ///
    /// # Errors
    ///
    /// Returns a body mismatch, or preserves the existing native issuer cause.
    pub fn prepare_once_v1(
        self,
        session: &AuthenticatedNodeSessionV1,
        body: NodeRequestBodyV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        if !matches!(&body, NodeRequestBodyV1::ReconcileDrain(directive)
            if directive.as_ref() == self.state.directive())
        {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        }
        self.owner
            .prepare_outbound_request(session, body, b"reconcile-drain")
            .map_err(Into::into)
    }
}

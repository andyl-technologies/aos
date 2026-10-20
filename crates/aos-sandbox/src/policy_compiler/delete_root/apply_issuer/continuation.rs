//! Borrows genuine completed predecessors for the same Root cleanup engines.

use super::*;
use crate::journal::JournalError;
use aos_sandbox_protocol::domain_ledger::delete_root::{
    final_inventory::{DeleteRootFreshFrameDataV2, DeleteRootPreparatoryApprovalDataV3},
    initial_inventory::DeleteRootInitialAckDataV3,
    resource_exchange::{DeleteRootNetworkPredecessorDataV4, DeleteRootResourcePurposeDataV3 as Purpose,
        DeleteRootResourceDraftDataV2, DeleteRootResourceSignedDataV2},
    transport::DeleteRootChallengeDataV2,
};

#[derive(Clone, Copy)]
pub(crate) struct RootDeleteResourceContinuationV4<'scope> {
    current: &'scope RootDeletePreparationCurrentOriginalV3,
    network: Option<NetworkPredecessorV4<'scope>>,
    mount: Option<MountPredecessorV4<'scope>>,
}

#[derive(Clone, Copy)]
struct NetworkPredecessorV4<'scope> {
    apply: &'scope RootDeleteApplyIssuerOriginalV3,
    controller: &'scope RootDeleteControllerCurrentOriginalV1,
    graph: &'scope RootDeleteGraphComparisonOriginalV2,
}

#[derive(Clone, Copy)]
struct MountPredecessorV4<'scope> {
    network: &'scope RootDeleteApplyIssuerOriginalV3,
    cleanup: &'scope RootDeleteCleanupCurrentOriginalV4,
    controller: &'scope RootDeleteControllerCurrentOriginalV1,
    graph: &'scope RootDeleteGraphComparisonOriginalV2,
    cache: &'scope RootDeleteCacheCurrentOriginalV2,
}

impl<'scope> RootDeleteResourceContinuationV4<'scope> {
    pub(crate) fn apply_v4(current: &'scope RootDeletePreparationCurrentOriginalV3) -> Self {
        Self { current, network: None, mount: None }
    }

    pub(super) fn network_v4(current: &'scope RootDeletePreparationCurrentOriginalV3,
        apply: &'scope RootDeleteApplyIssuerOriginalV3, controller: &'scope RootDeleteControllerCurrentOriginalV1,
        graph: &'scope RootDeleteGraphComparisonOriginalV2,
    ) -> Self {
        Self { current, network: Some(NetworkPredecessorV4 { apply, controller, graph }), mount: None }
    }

    pub(super) fn mount_v4(current: &'scope RootDeletePreparationCurrentOriginalV3,
        network: &'scope RootDeleteApplyIssuerOriginalV3, cleanup: &'scope RootDeleteCleanupCurrentOriginalV4,
        controller: &'scope RootDeleteControllerCurrentOriginalV1, graph: &'scope RootDeleteGraphComparisonOriginalV2,
        cache: &'scope RootDeleteCacheCurrentOriginalV2,
    ) -> Self {
        Self { current, network: None, mount: Some(MountPredecessorV4 {
            network, cleanup, controller, graph, cache,
        }) }
    }

    pub(crate) fn purpose_v4(self) -> Purpose {
        if self.mount.is_some() { Purpose::MountReap62 }
        else if self.network.is_some() { Purpose::Network9 } else { Purpose::Apply7 }
    }

    pub(crate) fn receiving_demand_v4(self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<DeleteRootNetworkPredecessorDataV4>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<blake3::Hasher>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(aos_sandbox_core::ResourceDimension::MemoryBytes, bytes))
    }

    pub(crate) fn require_completed_v3(self) -> Result<(), RootDeleteErrorV1> {
        self.current.require_completed_v3()?;
        if let Some(network) = self.network {
            network.apply.require_completed_v3()?;
            if network.apply.purpose != Some(Purpose::Apply7) { return Err(RootDeleteErrorV1::Original); }
        }
        if let Some(mount) = self.mount {
            mount.network.cleanup_network_approval_v4()?;
            mount.cleanup.require_completed_v4()?;
        }
        Ok(())
    }

    pub(in crate::policy_compiler::delete_root) fn completed_clock_v3(self) -> Result<aos_sandbox_core::RawPairedClockSample, RootDeleteErrorV1> {
        self.require_completed_v3()?;
        if let Some(mount) = self.mount { return mount.cleanup.completed_clock_v4(); }
        match self.network {
            None => self.current.completed_clock_v3(),
            Some(network) => network.apply.approval.completed_clock_v3(),
        }
    }

    pub(in crate::policy_compiler::delete_root) fn current_assignment_rows_v3(self)
        -> Result<aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'scope>, JournalError> {
        self.require_completed_v3().map_err(|_| JournalError::ProtectedBoundary)?;
        self.current.current_assignment_rows_v3()
    }

    pub(in crate::policy_compiler::delete_root) fn current_assignment_state_v3(self)
        -> Result<&'scope std::collections::BTreeMap<(crate::journal::RecordNamespace, Vec<u8>), Vec<u8>>, JournalError> {
        self.require_completed_v3().map_err(|_| JournalError::ProtectedBoundary)?;
        self.current.current_assignment_state_v3()
    }

    fn network_data_v4(self) -> Result<DeleteRootNetworkPredecessorDataV4, Box<dyn StdError>> {
        self.require_completed_v3()?;
        let network = self.network.ok_or(RootDeleteErrorV1::Original)?;
        let data = DeleteRootNetworkPredecessorDataV4 { current: self.current.completed_frame_data_v3()?,
            approval: network.apply.approval.completed_data_v4(Purpose::Apply7)? };
        data.commitment_v4()?;
        Ok(data)
    }

    pub(in crate::policy_compiler::delete_root) fn frame_commitment_v4(self) -> Result<[u8; 32], Box<dyn StdError>> {
        self.require_completed_v3()?;
        if let Some(mount) = self.mount { return Ok(mount.cleanup.completed_frame_v4()?.commitment_v4()?); }
        Ok(match self.network {
            None => self.current.completed_frame_data_v3()?.commitment_v3()?,
            Some(_) => self.network_data_v4()?.commitment_v4()?,
        })
    }

    pub(in crate::policy_compiler::delete_root) fn selection_v4(self,
        selected: crate::lifecycle::SelectedDeleteStoragePreparationDataV2,
        inputs: &RootDeleteCleanupInputsOriginalV2, challenge: &RootDeleteChallengeOriginalsV1,
    ) -> Result<crate::lifecycle::SelectedDeleteResourceDataV4, Box<dyn StdError>> {
        self.require_completed_v3()?;
        if self.mount.is_some() { return Err(RootDeleteErrorV1::Original.into()); }
        Ok(match self.network {
            None => selected.apply_data_v3(self.current.catalog_data_v3()?, self.current.completed_frame_data_v3()?)?,
            Some(network) => {
                let graph = network.graph.selection_data_v2()?;
                let query = challenge.source_query_v1()?;
                crate::lifecycle::select_first_local_delete_network_data_v4(graph.root, &graph.resources,
                    inputs.manifest_v2()?, network.controller.current_network_inventory_data_v4()?,
                    network.controller.current_network_lifecycle_data_v4()?,
                    aos_sandbox_core::OperationId::from_bytes(query.operation), query.nonce,
                    self.frame_commitment_v4()?)?
            }
        })
    }

    pub(in crate::policy_compiler::delete_root) fn require_approval_v4(self, approval: DeleteRootPreparatoryApprovalDataV3,
        frame: DeleteRootFreshFrameDataV2, challenge: DeleteRootChallengeDataV2,
        initial: DeleteRootInitialAckDataV3, draft: DeleteRootResourceDraftDataV2<'_>,
        signed: DeleteRootResourceSignedDataV2<'_>,
    ) -> Result<(), Box<dyn StdError>> {
        self.require_completed_v3()?;
        if let Some(mount) = self.mount {
            approval.require_mount_exchange_v4(frame, challenge, initial,
                mount.cleanup.completed_frame_v4()?, mount.network.cleanup_network_approval_v4()?, draft, signed)?;
            return Ok(());
        }
        match self.network {
            None => {
                let current = self.current.completed_frame_data_v3()?;
                approval.require_apply_exchange_v3(frame, challenge, initial, current, current.draft, draft, signed)?;
            }
            Some(_) => {
                let prior = self.network_data_v4()?;
                approval.require_network_exchange_v4(frame, challenge, initial, prior, prior.current.draft, draft, signed)?;
            }
        }
        Ok(())
    }

    pub(in crate::policy_compiler::delete_root) fn mount_cache_v4(self)
        -> Result<&'scope RootDeleteCacheCurrentOriginalV2, RootDeleteErrorV1> {
        self.require_completed_v3()?;
        self.mount.map(|mount| mount.cache).ok_or(RootDeleteErrorV1::Original)
    }

    pub(in crate::policy_compiler::delete_root) fn mount_request_v4(self,
        inputs: &RootDeleteCleanupInputsOriginalV2, spec: &super::super::mount_spec::RootDeleteMountSpecOriginalV4,
        challenge: &RootDeleteChallengeOriginalsV1,
    ) -> Result<aos_sandbox_protocol::mount_attachment_anchor::ValidatedAttachmentAnchorRequestV1, Box<dyn StdError>> {
        self.require_completed_v3()?;
        let mount = self.mount.ok_or(RootDeleteErrorV1::Original)?;
        let graph = mount.graph.selection_data_v2()?;
        if graph.resources.iter().any(|resource| match resource {
            aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Sandbox(id) => *id != graph.root,
            aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Snapshot(_)
                | aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Attachment(_) => true,
            _ => false,
        }) { return Err(JournalError::ProtectedBoundary.into()); }
        let manifest = inputs.manifest_v2()?;
        let inventory = mount.controller.current_mount_inventory_data_v4()?;
        if manifest.manifest().sandbox() != graph.root || !inventory.slots().is_empty() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let mut rows = inventory.namespace_anchors_v1().iter().filter(|row|
            row.fence().sandbox_id() == graph.root.as_bytes());
        let ready = rows.next().ok_or(JournalError::ProtectedBoundary)?;
        if rows.next().is_some() { return Err(JournalError::ProtectedBoundary.into()); }
        let query = challenge.source_query_v1()?;
        let (bytes, _) = spec.completed_spec_v4(manifest.manifest().sandbox_spec())?;
        Ok(aos_sandbox_protocol::mount_attachment_anchor::prepare_delete_mount_reap_request_data_v4(
            manifest, ready, &mount.cleanup.stopped_scope_v4()?, bytes,
            aos_sandbox_core::OperationId::from_bytes(query.operation), query.nonce,
            self.frame_commitment_v4()?, query.cutoff)?)
    }
}

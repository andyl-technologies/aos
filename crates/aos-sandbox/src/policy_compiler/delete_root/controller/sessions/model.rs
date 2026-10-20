//! Reconstructs each complete initial Session cut from Root's own captured file.
//!
//! The same local-manifest, Hello/context, full history/traffic and historical
//! method engines verify these DATA. The enclosing genuine Root owner pays
//! every stage and withholds outputs through its actual native EOF/after posts.
//! This capsule cannot construct a Session, a live query or a six-owner grant.

use crate::policy_compiler::create_storage_current::controller_readonly::{
    native_read::RootFixedNativeReadbackV1,
    storage_inventory::{
        RootCurrentStorageInventoryV1, RootHistoricalSessionPurposeV1,
        verify_session_for_purpose_v1,
    },
};
use crate::{
    journal::{JournalError, RecordNamespace},
    lifecycle::DeletePlanningBrokerInventoryDataV2,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableHistoryV1, BrokerSessionProtocolV1, BrokerSessionTrafficStateV1,
    ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    manifest::BrokerSessionManifestV1,
};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::{
    authenticated_session::{
        all_methods::AuthenticatedBrokerMethodOutcomeV1,
        historical_method::historical_terminal_outcome,
        stored_history::{
            StoredBrokerSessionHistoryDecodeCaptureV1, StoredBrokerSessionHistoryV1,
            canonical_protocol_key_v1,
        },
    },
    domain_ledger::{
        delete_batch::DeleteBatchOwnerCutDataV2,
        delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2,
    },
};
use std::{error::Error, mem::size_of};

type Cause = Box<dyn Error>;
type SessionValues = (
    ProtectedBrokerSessionVerificationContextV1,
    VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1,
    BrokerSessionTrafficStateV1,
);

#[derive(Clone, Copy)]
pub(in crate::policy_compiler::delete_root) enum DeleteCleanupTerminalPurposeV4 {
    NetworkDestroy9,
    HostInventory3,
    MountReap62,
    StorageDestroy7,
}

impl DeleteCleanupTerminalPurposeV4 {
    fn role_v4(self) -> DeleteBrokerRoleV2 {
        match self { Self::NetworkDestroy9 => DeleteBrokerRoleV2::Network,
            Self::HostInventory3 => DeleteBrokerRoleV2::Runtime,
            Self::MountReap62 => DeleteBrokerRoleV2::Mount,
            Self::StorageDestroy7 => DeleteBrokerRoleV2::Storage }
    }

    fn historical_purpose_v4(self) -> RootHistoricalSessionPurposeV1 {
        match self { Self::NetworkDestroy9 => RootHistoricalSessionPurposeV1::DeleteNetworkDestroy,
            Self::HostInventory3 => RootHistoricalSessionPurposeV1::DeleteHostTerminal,
            Self::MountReap62 => RootHistoricalSessionPurposeV1::DeleteMountReap,
            Self::StorageDestroy7 => RootHistoricalSessionPurposeV1::DeleteStorageDestroy }
    }
}

#[derive(Clone, Copy)]
pub(super) enum DeleteBrokerRoleV2 {
    Runtime,
    Mount,
    Storage,
    Network,
}

impl DeleteBrokerRoleV2 {
    pub(super) fn role(self) -> u8 {
        match self {
            Self::Runtime => 1,
            Self::Mount => 2,
            Self::Storage => 3,
            Self::Network => 4,
        }
    }
    pub(super) fn protocol(self) -> BrokerSessionProtocolV1 {
        match self {
            Self::Runtime => BrokerSessionProtocolV1::Host,
            Self::Mount => BrokerSessionProtocolV1::Mount,
            Self::Storage => BrokerSessionProtocolV1::Storage,
            Self::Network => BrokerSessionProtocolV1::Network,
        }
    }
}

#[derive(Default)]
pub(in crate::policy_compiler::delete_root) struct DeleteSessionModelsOriginalV2 {
    stored: StoredBrokerSessionHistoryDecodeCaptureV1,
    preparation: bool,
    cleanup: Option<DeleteCleanupTerminalPurposeV4>,
    cleanup_method: aos_sandbox_protocol::authenticated_session::historical_method::HistoricalDeleteCleanupMethodCaptureV4,
    preparation_prior: StoredBrokerSessionHistoryDecodeCaptureV1,
    preparation_prior_history: Option<Result<BrokerSessionDurableHistoryV1, Cause>>,
    preparation_join: Option<Result<(), Cause>>,
    preparation_method: aos_sandbox_protocol::authenticated_session::historical_method::HistoricalStorageMethodCaptureV1,
    native: Option<(aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1, u64, u64)>,
    verified: Option<Result<SessionValues, Cause>>,
    outcome: Option<Result<AuthenticatedBrokerMethodOutcomeV1, Cause>>,
    model: Option<Result<DeletePlanningBrokerInventoryDataV2, Cause>>,
    cut: Option<Result<DeleteBatchOwnerCutDataV2, Cause>>,
    observed: Option<Result<(), Cause>>,
    fresh: Option<Result<(), JournalError>>,
    entered: bool,
    closed: Option<JournalError>,
}

impl DeleteSessionModelsOriginalV2 {
    pub(super) fn packet_demand_v2(
        actual_prefix_bytes: usize,
        role: DeleteBrokerRoleV2,
    ) -> Result<ResourceVector, JournalError> {
        use aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1;
        // The shared Storage helper prices the complete stored/checkpoint/Hello
        // and common signed-request backing. Its namespace cells are not native
        // names; this new DATA-only consumer selects its actual memory plane.
        let common = RootCurrentStorageInventoryV1::additional_demand_v1(actual_prefix_bytes)?;
        let mut bytes = common.get(D::MemoryBytes);
        let method = aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::delete_inventory_method_for_role_data_v2(role.role())
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let one = AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(method, actual_prefix_bytes)
            .ok_or(JournalError::JournalTooLarge)?;
        bytes = bytes
            .checked_add(one.get(D::MemoryBytes))
            .ok_or(JournalError::JournalTooLarge)?;
        bytes = bytes
            .checked_add(
                u64::try_from(3 * size_of::<Self>()).map_err(|_| JournalError::JournalTooLarge)?,
            )
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    pub(in crate::policy_compiler::delete_root) fn preparation_packet_demand_v3(actual_prefix_bytes: usize)
        -> Result<ResourceVector, JournalError>
    {
        RootCurrentStorageInventoryV1::additional_demand_v1(actual_prefix_bytes)?
            .checked_add(RootCurrentStorageInventoryV1::additional_demand_v1(actual_prefix_bytes)?)
            .map_err(|_| JournalError::JournalTooLarge)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(3 * size_of::<Self>()).map_err(|_| JournalError::JournalTooLarge)?))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(in crate::policy_compiler::delete_root) fn observe_preparation_packets_once_v3(
        &mut self, actual: RootFixedNativeReadbackV1<'_>,
        selected: (&[u8], &[u8], &[u8]), manifest: &BrokerSessionManifestV1,
        cutoff: u64, boot: [u8;16],
    ) -> Result<(), JournalError> {
        self.observe_selected_terminal_once_v4(actual, selected, manifest, cutoff, boot, None)
    }

    pub(in crate::policy_compiler::delete_root) fn cleanup_packet_demand_v4(
        actual_prefix_bytes: usize, purpose: DeleteCleanupTerminalPurposeV4,
    ) -> Result<ResourceVector, JournalError> {
        // The same two raw history rows and full signed-request/outcome schema
        // recipe remain resident. Destroy9 adds no unbounded typed inventory.
        let demand = Self::preparation_packet_demand_v3(actual_prefix_bytes)?;
        match purpose {
            DeleteCleanupTerminalPurposeV4::NetworkDestroy9
                | DeleteCleanupTerminalPurposeV4::MountReap62
                | DeleteCleanupTerminalPurposeV4::StorageDestroy7 => Ok(demand),
            DeleteCleanupTerminalPurposeV4::HostInventory3 => {
                let host = aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::
                    AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(
                        aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
                        actual_prefix_bytes).ok_or(JournalError::JournalTooLarge)?;
                demand.checked_add(host).map_err(|_| JournalError::JournalTooLarge)
            }
        }
    }

    pub(in crate::policy_compiler::delete_root) fn observe_cleanup_packets_once_v4(
        &mut self, actual: RootFixedNativeReadbackV1<'_>,
        selected: (&[u8], &[u8], &[u8]), manifest: &BrokerSessionManifestV1,
        cutoff: u64, boot: [u8;16], purpose: DeleteCleanupTerminalPurposeV4,
    ) -> Result<(), JournalError> {
        self.observe_selected_terminal_once_v4(actual, selected, manifest, cutoff, boot, Some(purpose))
    }

    fn observe_selected_terminal_once_v4(
        &mut self, actual: RootFixedNativeReadbackV1<'_>,
        selected: (&[u8], &[u8], &[u8]), manifest: &BrokerSessionManifestV1,
        cutoff: u64, boot: [u8;16], cleanup: Option<DeleteCleanupTerminalPurposeV4>,
    ) -> Result<(), JournalError> {
        if self.entered || self.closed.is_some() || self.preparation || self.cleanup.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.preparation = cleanup.is_none();
        self.cleanup = cleanup;
        // Select the native transaction's actual PUT before the same full
        // decoder observes final state. Raw equality binds that complete result
        // to this COMMIT; a later matching map cannot substitute for its rows.
        let role = cleanup.map_or(DeleteBrokerRoleV2::Storage, DeleteCleanupTerminalPurposeV4::role_v4);
        let key = canonical_protocol_key_v1(role.protocol());
        let matches_selected = selected.0 == key
            && actual.state.get(&(RecordNamespace::BrokerSessionTraffic, key))
                .is_some_and(|bytes| bytes.as_slice() == selected.2);
        self.observe_packets_once_v2(actual, role, manifest, cutoff, boot)?;
        self.preparation_join = Some((|| {
            if !matches_selected { return Err(JournalError::ProtectedBoundary.into()); }
            StoredBrokerSessionHistoryV1::decode_retaining(selected.0, selected.1, &mut self.preparation_prior)?;
            let prior = self.preparation_prior.stored().ok_or(JournalError::ProtectedBoundary)?;
            self.preparation_prior_history = Some(prior.history_model().map_err(|cause| cause.into()));
            let prior_history = self.preparation_prior_history.as_ref()
                .and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
            let current = self.stored.stored().ok_or(JournalError::ProtectedBoundary)?;
            let (_, _, current_history, _) = self.verified.as_ref()
                .and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
            let prefix = current_history.records().len().checked_sub(1)
                .ok_or(JournalError::ProtectedBoundary)?;
            if prior.protocol != current.protocol || prior.endpoint != current.endpoint
                || prior.generation.checked_add(1) != Some(current.generation)
                || prior.stable_endpoint_identity != current.stable_endpoint_identity
                || prior.endpoint_publication != current.endpoint_publication
                || prior.checkpoint != current.checkpoint
                || prior_history.records() != &current_history.records()[..prefix]
                || prior_history.head()?.phase() != aos_sandbox_broker_session_protocol::BrokerSessionDurablePhaseV1::RequestPrepared
                || current_history.head()?.phase() != aos_sandbox_broker_session_protocol::BrokerSessionDurablePhaseV1::Terminal
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            // The shared current-history decoder above authenticated the exact
            // completed request/outcome. This predecessor join proves that
            // the selected transaction is its receipt append, not a re-PUT.
            Ok(())
        })());
        if matches!(self.preparation_join, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(super) fn observe_packets_once_v2(
        &mut self,
        actual: RootFixedNativeReadbackV1<'_>,
        role: DeleteBrokerRoleV2,
        manifest: &BrokerSessionManifestV1,
        authorization_cutoff: u64,
        boot: [u8; 16],
    ) -> Result<(), JournalError> {
        if self.entered || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.entered = true;
        self.observed =
            Some(self.observe_inner(actual, role, manifest, authorization_cutoff, boot));
        if matches!(self.observed, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn observe_inner(
        &mut self,
        actual: RootFixedNativeReadbackV1<'_>,
        role: DeleteBrokerRoleV2,
        manifest: &BrokerSessionManifestV1,
        authorization_cutoff: u64,
        boot: [u8; 16],
    ) -> Result<(), Cause> {
        self.native = Some((actual.names, actual.next, actual.end));
        if role.protocol() == BrokerSessionProtocolV1::Storage {
            crate::policy_compiler::create_storage_current::controller_readonly::storage_inventory::
                verify_storage_history_roster_v2(actual.state, manifest, manifest.node_id(), boot)?;
        }
        let key = canonical_protocol_key_v1(role.protocol());
        let bytes = actual
            .state
            .get(&(RecordNamespace::BrokerSessionTraffic, key.clone()))
            .ok_or(JournalError::ProtectedBoundary)?;
        StoredBrokerSessionHistoryV1::decode_retaining(&key, bytes, &mut self.stored)?;
        let stored = self
            .stored
            .stored()
            .ok_or(JournalError::ProtectedBoundary)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let history = stored.history_model()?;
        let head = history.head()?;
        self.verified = Some(verify_session_for_purpose_v1(manifest, stored,
            checkpoint.client_hello_bytes(), checkpoint.broker_hello_bytes(), manifest.node_id(), boot,
            head.method(), head.request_packet(), head.outcome_packet().ok_or(JournalError::ProtectedBoundary)?,
            if let Some(cleanup) = self.cleanup { cleanup.historical_purpose_v4() }
            else if self.preparation { RootHistoricalSessionPurposeV1::DeletePreparation }
            else { RootHistoricalSessionPurposeV1::DeleteInventory(role.protocol(),
                aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::delete_inventory_method_for_role_data_v2(role.role())?) }));
        let (_, transcript, history, _) = self
            .verified
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let terminal = history
            .records()
            .len()
            .checked_sub(1)
            .ok_or(JournalError::ProtectedBoundary)?;
        // This is the existing historical comparator, not a renewed live
        // request or a caller-chosen time supplied to an authorization engine.
        if let Some(cleanup) = self.cleanup {
            match cleanup {
                DeleteCleanupTerminalPurposeV4::NetworkDestroy9 => self.cleanup_method.observe_network_destroy_once_v4(
                    history.records(), terminal, checkpoint, transcript)?,
                DeleteCleanupTerminalPurposeV4::HostInventory3 => self.cleanup_method.observe_host_inventory_once_v4(
                    history.records(), terminal, checkpoint, transcript)?,
                DeleteCleanupTerminalPurposeV4::MountReap62 => self.cleanup_method.observe_mount_reap_once_v4(
                    history.records(), terminal, checkpoint, transcript)?,
                DeleteCleanupTerminalPurposeV4::StorageDestroy7 => self.cleanup_method.observe_storage_destroy_once_v4(
                    history.records(), terminal, checkpoint, transcript)?,
            }
        } else if self.preparation {
            self.preparation_method.observe_once_v1(history.records(), terminal, checkpoint, transcript)?;
        } else {
            self.outcome = Some(
                historical_terminal_outcome(history.records(), terminal, checkpoint, transcript)
                    .map_err(|cause| Box::new(cause) as Cause),
            );
        }
        let outcome = self.outcome_v2()?;
        if authorization_cutoff == 0
            || outcome.request().request_id() == [0; 16]
            || outcome.request().deadline_boottime_nanoseconds() == 0
            || outcome.request().deadline_boottime_nanoseconds() > authorization_cutoff
            || (outcome.request().authorization().is_some() != (self.preparation
                || matches!(self.cleanup, Some(DeleteCleanupTerminalPurposeV4::NetworkDestroy9
                    | DeleteCleanupTerminalPurposeV4::MountReap62 | DeleteCleanupTerminalPurposeV4::StorageDestroy7))))
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    // The old four-role supplier and this reached-role supplier share one
    // concrete decoder/row recipe. The actual Root stage admits it before
    // constructing this role's complete model.
    pub(super) fn model_demand_v2(
        &self,
        role: DeleteBrokerRoleV2,
    ) -> Result<ResourceVector, JournalError> {
        let outcome = self.outcome_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        crate::lifecycle::delete_planning_broker_inventory_role_receiving_demand_v2(
            role.role(), outcome,
        ).ok_or(JournalError::JournalTooLarge)
    }

    // Called only after the genuine R admits this actual outcome's complete
    // model planes. Earlier packet/history/native originals remain held.
    pub(super) fn finish_model_once_v2(
        &mut self,
        actual: RootFixedNativeReadbackV1<'_>,
        role: DeleteBrokerRoleV2,
        boot: [u8; 16],
    ) -> Result<(), JournalError> {
        if !matches!(self.observed, Some(Ok(()))) || self.model.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.model = Some(self.outcome_v2().and_then(|outcome| {
            DeletePlanningBrokerInventoryDataV2::from_outcome_data_v2(role.role(), outcome, boot)
                .map_err(|cause| Box::new(cause) as Cause)
        }));
        self.cut = Some((|| {
            let outcome = self.outcome_v2()?;
            let stored = self
                .stored
                .stored()
                .ok_or(JournalError::ProtectedBoundary)?;
            let model = self
                .model
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let (count, generation, commitment) = model
                .complete_model_data_v2()
                .ok_or(JournalError::ProtectedBoundary)?;
            let (device, inode) = actual.names.journal();
            Ok(DeleteSessionInventoryCutDataV2 {
                role: role.role(),
                outcome,
                kernel_boot: boot,
                native: (actual.next, device, inode, actual.end),
                protected: (stored.generation, stored.current_head),
                inventory: (generation, commitment),
                count,
            }
            .owner_cut_data_v2()?)
        })());
        if matches!(self.cut, Some(Ok(_))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    // Both sides are completed actual packet/model owners from separate paid
    // native reads. These DATA comparisons never construct a fresh Session.
    pub(super) fn require_fresh_after_v2(
        &mut self,
        initial: &Self,
        nonce: [u8; 16],
        cutoff: u64,
    ) -> Result<(), JournalError> {
        if self.fresh.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.fresh = Some((|| {
            self.cut_v2()?;
            initial.cut_v2()?;
            let (names, next, end) = self.native.ok_or(JournalError::ProtectedBoundary)?;
            let (old_names, old_next, old_end) = initial.native
                .ok_or(JournalError::ProtectedBoundary)?;
            let stored = self.stored.stored().ok_or(JournalError::ProtectedBoundary)?;
            let old_stored = initial.stored.stored().ok_or(JournalError::ProtectedBoundary)?;
            let outcome = self.outcome_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            let old_outcome = initial.outcome_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            let request = outcome.request();
            let old_request = old_outcome.request();
            if names != old_names || next <= old_next || end <= old_end
                || stored.generation <= old_stored.generation
                || stored.current_head == old_stored.current_head
                || request.method() != old_request.method()
                || request.session_binding() != old_request.session_binding()
                || request.request_id() != nonce || nonce == [0; 16]
                || request.request_id() == old_request.request_id()
                || request.client_sequence() <= old_request.client_sequence()
                || outcome.broker_sequence() <= old_outcome.broker_sequence()
                || request.deadline_boottime_nanoseconds() == 0
                || request.deadline_boottime_nanoseconds() > cutoff
                || request.authorization().is_some()
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })());
        if matches!(self.fresh, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::StaleAuthoritySnapshot) }
    }

    pub(in crate::policy_compiler::delete_root) fn outcome_v2(&self) -> Result<&AuthenticatedBrokerMethodOutcomeV1, Cause> {
        if self.closed.is_some() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        if self.cleanup.is_some() {
            self.cleanup_method.outcome_v4().ok_or_else(|| JournalError::ProtectedBoundary.into())
        } else if self.preparation {
            self.preparation_method.outcome_v1().ok_or_else(|| JournalError::ProtectedBoundary.into())
        } else {
            self.outcome.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or_else(|| JournalError::ProtectedBoundary.into())
        }
    }

    pub(in crate::policy_compiler::delete_root) fn preparation_response_data_v3(&self)
        -> Result<&aos_proto::aos::sandbox::local::v1::PrepareStorageCatalogResponse, JournalError>
    {
        if !self.preparation || !matches!(self.observed, Some(Ok(())))
            || !matches!(self.preparation_join, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.preparation_method.storage_preparation_response_data_v3()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(in crate::policy_compiler::delete_root) fn completed_cleanup_outcome_v4(&self)
        -> Result<&AuthenticatedBrokerMethodOutcomeV1, JournalError> {
        if self.cleanup.is_none() || !matches!(self.observed, Some(Ok(())))
            || !matches!(self.preparation_join, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.cleanup_method.outcome_v4().ok_or(JournalError::ProtectedBoundary)
    }

    pub(in crate::policy_compiler::delete_root) fn completed_host_inventory_v4(&self)
        -> Result<&aos_proto::aos::sandbox::local::v1::InventoryRuntimeResponse, JournalError> {
        self.completed_cleanup_outcome_v4()?;
        if !matches!(self.cleanup, Some(DeleteCleanupTerminalPurposeV4::HostInventory3)) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.cleanup_method.host_inventory_v4().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn storage_inventory_data_v2(&self)
        -> Result<&aos_sandbox_protocol::ValidatedStorageInventory, super::super::super::RootDeleteErrorV1>
    {
        self.cut_v2().map_err(|_| super::super::super::RootDeleteErrorV1::Original)?;
        self.model.as_ref().and_then(|value| value.as_ref().ok())
            .and_then(DeletePlanningBrokerInventoryDataV2::storage_inventory_data_v2)
            .ok_or(super::super::super::RootDeleteErrorV1::Original)
    }

    pub(super) fn mount_inventory_data_v4(&self)
        -> Result<&aos_sandbox_protocol::ValidatedDestinationSlotInventory, super::super::super::RootDeleteErrorV1>
    {
        self.cut_v2().map_err(|_| super::super::super::RootDeleteErrorV1::Original)?;
        self.model.as_ref().and_then(|value| value.as_ref().ok())
            .and_then(DeletePlanningBrokerInventoryDataV2::mount_inventory_data_v2)
            .ok_or(super::super::super::RootDeleteErrorV1::Original)
    }

    pub(super) fn storage_lifecycle_data_v2(&self)
        -> Result<&crate::lifecycle::LifecycleAuthenticatedStorageInventoryV1, super::super::super::RootDeleteErrorV1>
    {
        self.cut_v2().map_err(|_| super::super::super::RootDeleteErrorV1::Original)?;
        self.model.as_ref().and_then(|value| value.as_ref().ok())
            .and_then(DeletePlanningBrokerInventoryDataV2::storage_lifecycle_data_v2)
            .ok_or(super::super::super::RootDeleteErrorV1::Original)
    }

    pub(super) fn cut_v2(&self) -> Result<DeleteBatchOwnerCutDataV2, JournalError> {
        if self.closed.is_some() || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.cut
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn require_cleanup_host_successor_v4(&self, outcome: &AuthenticatedBrokerMethodOutcomeV1,
        position: [u8; 64],
    ) -> Result<(), JournalError> {
        use aos_proto::aos::sandbox::local::v1::BrokerMethod;
        self.cut_v2()?;
        let old = self.outcome_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        let current = aos_sandbox_protocol::domain_ledger::protected_names::SessionCompletionPositionDataV4::decode_v4(&position)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let (names, next, end) = self.native.ok_or(JournalError::ProtectedBoundary)?;
        if old.method() != BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
            || outcome.method() != old.method() || outcome.request().authorization().is_some()
            || outcome.request().session_binding() != old.request().session_binding()
            || outcome.request().request_id() == old.request().request_id()
            || outcome.request().client_sequence() <= old.request().client_sequence()
            || outcome.broker_sequence() <= old.broker_sequence()
            || current.names_v4() != names || current.next_sequence_v4() <= next
            || current.held_bytes_v4() <= end {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(super) fn network_inventory_data_v4(&self)
        -> Result<&aos_sandbox_protocol::ValidatedNetworkInventory, super::super::super::RootDeleteErrorV1> {
        self.cut_v2().map_err(|_| super::super::super::RootDeleteErrorV1::Original)?;
        self.model.as_ref().and_then(|value| value.as_ref().ok())
            .and_then(DeletePlanningBrokerInventoryDataV2::network_inventory_data_v4)
            .ok_or(super::super::super::RootDeleteErrorV1::Original)
    }

    pub(super) fn network_lifecycle_data_v4(&self)
        -> Result<&crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryV1, super::super::super::RootDeleteErrorV1> {
        self.cut_v2().map_err(|_| super::super::super::RootDeleteErrorV1::Original)?;
        self.model.as_ref().and_then(|value| value.as_ref().ok())
            .and_then(DeletePlanningBrokerInventoryDataV2::network_lifecycle_data_v4)
            .ok_or(super::super::super::RootDeleteErrorV1::Original)
    }

    pub(in crate::policy_compiler::delete_root) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.stored
            .failure()
            .map(|cause| cause as _)
            .or_else(|| self.preparation_method.failure_v1())
            .or_else(|| self.cleanup_method.failure_v4())
            .or_else(|| {
                self.verified
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.outcome
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.observed
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.model
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.cut
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| self.preparation_prior.failure().map(|cause| cause as _))
            .or_else(|| self.preparation_prior_history.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.preparation_join.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.fresh.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

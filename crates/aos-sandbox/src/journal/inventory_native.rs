//! Shares finite Session Inventory native mechanics without a financial factory.
//!
//! Genuine D or authorized Recover loans must prepay and keep their actual
//! Session and source/current-C originals exclusive. This module supplies no
//! role, budget, caller-vector constructor, Journal or File extraction.

pub(crate) mod io;
use super::*;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_broker_session_protocol::{BrokerSessionProtocolV1, VerifiedBrokerSessionTranscriptV1};
use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod};
use crate::ControllerInitialBrokerSessionRoleV1 as Role;

pub(crate) fn inventory_recipe(transcript: &VerifiedBrokerSessionTranscriptV1)
    -> Result<(Role, BrokerMethod), JournalError>
{
    if transcript.audience() != Audience::AUDIENCE_NODE_CONTROLLER {
        return Err(JournalError::ProtectedBoundary);
    }
    let recipe = match transcript.protocol() {
        BrokerSessionProtocolV1::Host => (Role::Host, BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME),
        BrokerSessionProtocolV1::Mount => (Role::Mount, BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS),
        BrokerSessionProtocolV1::Storage => (Role::Storage, BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES),
        BrokerSessionProtocolV1::Network => (Role::Network, BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES),
        _ => return Err(JournalError::ProtectedBoundary),
    };
    if !transcript.negotiated_methods().contains(&recipe.1) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(recipe)
}


use super::native_interval::captured::{CapturedAppendOwnerV1, DeleteSessionAppendWindowV1};

pub(crate) fn append_geometry_v2(journal: &Journal,
    extent: &ProtectedJournalPreopenReplayExtentV1,
    future: &ProtectedJournalPreopenReplayExtentV1, encoded: u64,
    method: BrokerMethod, directory: &'static str,
) -> Result<ResourceVector, JournalError> {
    let mut demand = CapturedAppendOwnerV1::append_demand_for_fixed_v1(
        directory, "session.journal", encoded,
    )?.checked_add(ResourceVector::ZERO.with(D::StorageBytes, encoded))
        .map_err(JournalError::ReceivingAccounting)?;
    // Captured DATA append retains the real native preflight/indexes
    // and full semantic replay through the future two-TX prefix. The
    // body codec term below cannot substitute for these namespaces or
    // deleted/overwritten historical values.
    let native_replay = future.dominant_native_receiving_demand_v1()?;
    let semantic_replay = future.dominant_semantic_receiving_demand_v1()?;
    let current_replay = crate::journal::broker_session_receiving::
        storage_retained_current_replay_demand_v1(future)
        .map_err(|_| JournalError::LimitExceeded("Delete Inventory current replay"))?;
    let traffic_replay = crate::journal::broker_session_receiving::
        storage_retained_traffic_reconstruction_demand_v1(future)
        .map_err(|_| JournalError::LimitExceeded("Delete Inventory traffic replay"))?;
    let future_prefix = usize::try_from(future.native_bytes)
        .map_err(|_| JournalError::LimitExceeded("Delete Inventory terminal prefix"))?;
    let terminal_model = aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::
        AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(
            method, future_prefix,
        ).ok_or(JournalError::LimitExceeded("Delete Inventory terminal replay"))?;
    demand = demand.checked_add(native_replay)
        .and_then(|value| value.checked_add(semantic_replay))
        .and_then(|value| value.checked_add(current_replay))
        .and_then(|value| value.checked_add(traffic_replay))
        .and_then(|value| value.checked_add(terminal_model))
        .map_err(JournalError::ReceivingAccounting)?;
    let schema = crate::journal::broker_session_receiving::schema_demand(extent)
        .map_err(|_| JournalError::LimitExceeded("Delete Inventory held schema"))?;
    let initialization = crate::journal::broker_session_receiving::initialization_demand(extent)
        .map_err(|_| JournalError::LimitExceeded("Delete Inventory initialization"))?;
    let request = crate::journal::broker_session_receiving::storage_inventory_client_request_demand_v1(extent)
        .map_err(|_| JournalError::LimitExceeded("Delete Inventory request"))?;
    let prefix = usize::try_from(extent.native_bytes)
        .map_err(|_| JournalError::LimitExceeded("Delete Inventory prefix"))?;
    let body = aos_sandbox_protocol::authenticated_session::all_methods::outcome_capture::
        AuthenticatedBrokerMethodOutcomeCaptureV1::controller_inventory_dynamic_receiving_demand_v1(
            method, prefix,
        ).ok_or(JournalError::LimitExceeded("Delete Inventory held body"))?;
    // The fixed two-append window above already owns all native log
    // bytes. Request formation adds its actual model/backing only.
    let request = ResourceVector::ZERO.with(D::MemoryBytes, request.get(D::MemoryBytes));
    demand = demand.checked_add(schema).and_then(|value| value.checked_add(initialization))
        .and_then(|value| value.checked_add(request)).and_then(|value| value.checked_add(body))
        .map_err(JournalError::ReceivingAccounting)?;
    let window = DeleteSessionAppendWindowV1::construction_bytes_v1()
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(JournalError::LimitExceeded("Delete Inventory append window"))?;
    demand = demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, window))
        .map_err(JournalError::ReceivingAccounting)?;
    if !journal.has_captured_append_custody_v1() {
        demand = demand.checked_add(CapturedAppendOwnerV1::construction_demand_v1()
            .ok_or(JournalError::LimitExceeded("Delete Inventory captured sink"))?)
            .map_err(JournalError::ReceivingAccounting)?;
    }
    Ok(demand)
}

/// Retains the one exact finite request/terminal window on a held native writer.
///
/// This is mechanical custody only. Private D/Recover callers must first join
/// their genuine continuously held original and pay the entire geometry above.
#[derive(Default)]
pub(crate) struct InventoryAppendWindowOriginalV2 {
    window: Option<Arc<DeleteSessionAppendWindowV1>>,
    entered: bool,
    temporary: bool,
    installation: Option<Result<(), JournalError>>,
    retirement: Option<Result<(), JournalError>>,
}

impl InventoryAppendWindowOriginalV2 {
    pub(crate) fn install_prepaid_once_v2(&mut self, journal: &mut Journal,
        directory: &'static str, uid: u32, encoded: u64,
    ) -> Result<(), JournalError> {
        if self.entered { return Err(JournalError::ProtectedBoundary); }
        self.entered = true;
        self.window = Some(Arc::new(DeleteSessionAppendWindowV1::new_prepaid_v1(encoded)));
        let window = self.window.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.installation = Some((|| {
            let super::native_backing::JournalNativeBackingV1::Ordinary(ordinary) = &mut journal.native
            else { return Err(JournalError::ProtectedBoundary); };
            if ordinary.captured_append.is_none() {
                ordinary.captured_append = Some(CapturedAppendOwnerV1::new(directory, "session.journal", uid));
                self.temporary = true;
            }
            let owner = ordinary.captured_append.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            owner.require_delete_identity_v1(directory, "session.journal", uid)?;
            owner.install_delete_window_v1(Arc::clone(window))?;
            window.open_primary_once_v1()
        })());
        if matches!(self.installation, Some(Ok(()))) { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn close_if_owed_v2(&self) {
        if let Some(window) = &self.window { window.close_primary_v1(); }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.installation.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.window.as_ref().and_then(|window| window.failure()))
            .or_else(|| self.retirement.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
    }

    pub(crate) fn prepare_retirement_v2<'positive>(&'positive mut self,
        journal: &'positive mut Journal,
    ) -> Result<InventoryAppendWindowDisposalV2<'positive>, JournalError> {
        if self.retirement.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.retirement = Some((|| {
            if self.failure().is_some() || journal.native_interval.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            let window = self.window.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            let super::native_backing::JournalNativeBackingV1::Ordinary(ordinary) = &journal.native
            else { return Err(JournalError::ProtectedBoundary); };
            ordinary.captured_append.as_ref().ok_or(JournalError::ProtectedBoundary)?
                .require_delete_window_retirement_v1(window)
        })());
        if !matches!(self.retirement, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        let super::native_backing::JournalNativeBackingV1::Ordinary(ordinary) = &mut journal.native
        else { return Err(JournalError::ProtectedBoundary); };
        Ok(InventoryAppendWindowDisposalV2 {
            original: self, captured: &mut ordinary.captured_append, completed: false,
        })
    }
}

pub(crate) struct InventoryAppendWindowDisposalV2<'positive> {
    original: &'positive mut InventoryAppendWindowOriginalV2,
    captured: &'positive mut Option<CapturedAppendOwnerV1>,
    completed: bool,
}

impl InventoryAppendWindowDisposalV2<'_> {
    pub(crate) fn complete_after_upper_disposal(mut self) {
        if self.original.temporary {
            drop(self.captured.take());
        } else {
            match self.captured.as_mut() {
                Some(owner) => owner.complete_delete_window_retirement_v1(),
                None => std::process::abort(),
            }
        }
        drop(self.original.window.take());
        self.completed = true;
    }
}

impl Drop for InventoryAppendWindowDisposalV2<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.original.retirement = Some(Err(JournalError::ProtectedBoundary));
        }
    }
}

/// Projects only the same successful final native sample; it performs no IO.
pub(crate) fn completed_boundary_data_v2(journal: &Journal,
    original: &super::ProtectedJournalCurrentnessOriginalsV1,
) -> Option<(u64, u64, u64, u64)> {
    let (device, inode, bytes) = original.completed_held_file_boundary_data_v1()?;
    Some((journal.native.next_sequence(), device, inode, bytes))
}

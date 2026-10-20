//! Selects finite actual Recover and reconciliation loans for one native query.

use super::*;
use crate::controller_resource_reservation::operator_create_recovery::reconciliation::{
    OperatorReconciliationObservationLoanV2, ControllerReconciliationInventoryRoleV2 as Role,
};

#[derive(Clone, Copy)]
pub(super) struct InventoryContextV2 {
    pub(super) directory: &'static str,
    pub(super) protocol: BrokerSessionProtocolV1,
    pub(super) method: BrokerMethod,
    pub(super) storage_recover: bool,
    pub(super) stop_cleanup: bool,
}

impl InventoryContextV2 {
    pub(super) fn matches_transcript_v2(self, transcript: &VerifiedBrokerSessionTranscriptV1) -> bool {
        if self.storage_recover {
            aos_sandbox_broker_session_protocol::profile::is_storage_operator_recover_transcript_v1(transcript)
        } else if self.stop_cleanup {
            aos_sandbox_broker_session_protocol::profile::is_host_stop_cleanup_transcript_v1(transcript)
        } else {
            transcript.protocol() == self.protocol
                && transcript.audience() == aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                && transcript.negotiated_methods().contains(&self.method)
        }
    }
}

pub(in crate::controller_resource_reservation) enum RecoveryInventorySourceV2<'query, 'owner, 'controller, 'seed, 'completed> {
    Storage(&'query mut OperatorCreateRecoveryLoanV1<'owner, 'controller>),
    StopCleanup(&'query mut crate::OperatorStopCleanupObservationLoanV1<'owner, 'controller>),
    StopSource {
        source: &'query mut crate::controller_lifecycle_stop::ControllerHostStopCleanupSourceLoanV1<'owner, 'controller>,
        controller: &'query mut Journal,
        index: usize,
    },
    Maintenance {
        source: &'query mut crate::controller_resource_reservation::catalog_maintenance::ControllerCatalogMaintenanceLoanV2<'owner, 'controller>,
        index: usize,
        context: InventoryContextV2,
    },
    Reconciliation {
        source: &'query mut OperatorReconciliationObservationLoanV2<'owner, 'seed, 'completed, 'controller>,
        index: usize,
        context: InventoryContextV2,
    },
}

impl<'query, 'owner, 'controller, 'seed, 'completed>
    RecoveryInventorySourceV2<'query, 'owner, 'controller, 'seed, 'completed>
{
    pub(in crate::controller_resource_reservation) fn maintenance_v2(
        source: &'query mut crate::controller_resource_reservation::catalog_maintenance::ControllerCatalogMaintenanceLoanV2<'owner, 'controller>,
        index: usize,
    ) -> Result<Self, ResourceReservationErrorV1> {
        let context = maintenance_context_v2(index)?;
        Ok(Self::Maintenance { source, index, context })
    }

    pub(super) fn state_v2(&self) -> &InventoryOriginalsV1 {
        match self {
            Self::Storage(source) => &source.owner.storage.inventory,
            Self::StopCleanup(source) => &source.inner.owner.storage.inventory,
            Self::StopSource { source, index, .. } => source.state_v1(*index),
            Self::Reconciliation { source, index, .. } => &source.owner.inventory[*index],
            Self::Maintenance { source, index, .. } => source.state_v2(*index),
        }
    }

    pub(super) fn state_mut_v2(&mut self) -> &mut InventoryOriginalsV1 {
        match self {
            Self::Storage(source) => &mut source.owner.storage.inventory,
            Self::StopCleanup(source) => &mut source.inner.owner.storage.inventory,
            Self::StopSource { source, index, .. } => source.state_mut_v1(*index),
            Self::Reconciliation { source, index, .. } => &mut source.owner.inventory[*index],
            Self::Maintenance { source, index, .. } => source.state_mut_v2(*index),
        }
    }

    pub(super) fn context_v2(&self) -> InventoryContextV2 {
        match self {
            Self::Storage(_) => InventoryContextV2 { directory: DIRECTORY,
                protocol: BrokerSessionProtocolV1::Storage, method: METHOD, storage_recover: true, stop_cleanup: false },
            Self::StopCleanup(_) | Self::StopSource { .. } => InventoryContextV2 {
                directory: crate::journal::controller_session_directory_data_v1(crate::ControllerInitialBrokerSessionRoleV1::Host),
                protocol: BrokerSessionProtocolV1::Host,
                method: BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
                storage_recover: false, stop_cleanup: true,
            },
            Self::Reconciliation { context, .. } | Self::Maintenance { context, .. } => *context,
        }
    }

    pub(super) fn require_current_v1(&mut self) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Storage(source) => source.require_current_v1(),
            Self::StopCleanup(source) => source.inner.require_current_v1(),
            Self::StopSource { source, controller, .. } => source.require_current_v1(controller),
            Self::Reconciliation { source, .. } => source.require_current_v2(),
            Self::Maintenance { source, .. } => source.require_current_v2(),
        }
    }

    pub(super) fn check_frontier_v1(&mut self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        match self {
            Self::Storage(source) => source.check_frontier_v1(),
            Self::StopCleanup(source) => source.inner.check_frontier_v1(),
            Self::StopSource { source, controller, .. } => source.host_check_frontier_v1(controller),
            Self::Reconciliation { source, .. } => source.check_frontier_v2(),
            Self::Maintenance { source, .. } => source.check_frontier_v2(),
        }
    }

    pub(super) fn reserve_additional_v1(&mut self, demand: ResourceVector) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Storage(source) => source.reserve_additional_v1(demand),
            Self::StopCleanup(source) => source.reserve_additional_v1(demand),
            Self::StopSource { source, controller, .. } => source.reserve_additional_v1(controller, demand),
            Self::Reconciliation { source, .. } => source.reserve_additional_v2(demand),
            Self::Maintenance { source, .. } => source.reserve_additional_v2(demand),
        }
    }

    pub(in crate::controller_resource_reservation) fn begin_query_v2(mut self, receiving: &ControllerInitialBrokerSessionReceivingV1,
        journal: &Journal, shape: crate::DeleteInventorySecurityShapeDataV1,
    ) -> Result<ControllerRecoveryInventoryLoanV2<'query, 'owner, 'controller, 'seed, 'completed>, ResourceReservationErrorV1> {
        let context = self.context_v2();
        if self.state_mut_v2().entered || self.state_mut_v2().borrowed {
            self.state_mut_v2().refuse();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let retain_cookie_originals = matches!(&self, Self::Maintenance { .. });
        self.state_mut_v2().entered = true;
        self.state_mut_v2().retain_cookie_originals = retain_cookie_originals;
        self.state_mut_v2().shape = Some(shape);
        let demand = (|| {
            self.require_current_v1()?;
            self.check_frontier_v1()?;
            let key = u64::try_from(3 * aos_sandbox_protocol::authenticated_session::stored_history::canonical_protocol_key_receiving_bytes_v1()).map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let fixed = shape.demand_v1()?.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, key))?;
            let one = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
                std::path::Path::new(context.directory), "session.journal")?;
            let native = one.checked_add(one)?.checked_add(one)?.checked_add(IoOriginals::fixed_demand(context.directory)?)?;
            let bytes = u64::try_from(3 * std::mem::size_of::<ControllerRecoveryInventoryLoanV2<'_, '_, '_, '_, '_>>())
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            self.reserve_additional_v1(fixed.checked_add(native)?.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
        })();
        self.state_mut_v2().fixed = Some(demand);
        if !matches!(self.state_mut_v2().fixed, Some(Ok(()))) {
            self.state_mut_v2().first = Some(First::Fixed);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let cutoff = self.original_cutoff_v1()?;
        let original = self.require_completed_cold_v2(receiving, journal, cutoff);
        self.state_mut_v2().original = Some(original);
        if !matches!(self.state_mut_v2().original, Some(Ok(()))) {
            self.state_mut_v2().first = Some(First::Original);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.state_mut_v2().cutoff = cutoff;
        self.state_mut_v2().uid = rustix::process::geteuid().as_raw();
        let state = self.state_mut_v2();
        state.entropy = Some(rustix::rand::getrandom(&mut state.nonce, rustix::rand::GetRandomFlags::empty()));
        state.nonce_comparison = Some(if matches!(state.entropy, Some(Ok(16))) && state.nonce != [0; 16] {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        });
        if !matches!(state.nonce_comparison, Some(Ok(()))) {
            state.first = Some(First::Entropy);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.state_mut_v2().borrowed = true;
        Ok(ControllerRecoveryInventoryLoanV2 { source: self })
    }

    fn original_cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        match self {
            Self::Storage(source) => source.original_cutoff_v1(),
            Self::StopCleanup(source) => source.inner.original_cutoff_v1(),
            Self::StopSource { source, controller, .. } => source.host_cutoff_data_v1(controller),
            Self::Reconciliation { source, .. } => source.original_cutoff_v2(),
            Self::Maintenance { source, .. } => source.original_cutoff_v2(),
        }
    }

    pub(super) fn retain_storage_sdk_refusal_once_v1(&mut self) {
        match self {
            Self::Storage(source) => source.retain_storage_sdk_refusal_once_v1(),
            Self::StopCleanup(source) => source.retain_sdk_refusal_once_v1(),
            Self::StopSource { source, .. } => source.retain_cold_sdk_refusal_v1(),
            Self::Reconciliation { source, .. } => source.retain_sdk_refusal_once_v2(),
            Self::Maintenance { source, .. } => source.retain_sdk_refusal_once_v2(),
        }
    }

    fn require_completed_cold_v2(&self, receiving: &ControllerInitialBrokerSessionReceivingV1,
        journal: &Journal, cutoff: u64,
    ) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::StopSource { source, controller, .. } => source.require_completed_cold_session_v1(controller, receiving, journal),
            Self::StopCleanup(source) => receiving.require_completed_stop_cleanup_journal_v1(
                source.inner.owner.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?, journal, cutoff),
            Self::Storage(source) => receiving.require_completed_recover_journal_v1(
                source.owner.native.as_ref().map_err(|_| ResourceReservationErrorV1::Conflict)?, journal, cutoff),
            Self::Reconciliation { source, .. } => source.require_completed_cold_v2(receiving, journal),
            Self::Maintenance { source, index, .. } => source.require_completed_session_v2(receiving, journal, *index),
        }
    }
}

impl<'owner, 'seed, 'completed, 'controller>
    OperatorReconciliationObservationLoanV2<'owner, 'seed, 'completed, 'controller>
{
    fn inventory_context_v2(&self, index: usize) -> Result<InventoryContextV2, ResourceReservationErrorV1> {
        context_for_role_v2(self.role_v2(), index)
    }

    /// Reports the finite method selected by this actual role and query ordinal.
    ///
    /// # Errors
    /// Refuses another ordinal or an unavailable actual receiving context.
    pub fn inventory_method_data_v2(&self, index: usize) -> Result<BrokerMethod, ResourceReservationErrorV1> {
        self.require_current_v2()?;
        self.inventory_context_v2(index).map(|context| context.method)
    }

    /// Borrows the next finite native query of this actual endpoint.
    ///
    /// Each role admits only index zero. The selected Mount16 producer supplies
    /// its complete physical absence companion without unsupported methods.
    ///
    /// # Errors
    /// Refuses an unsupported index, missing prior completion, another cold
    /// Session, expiry, native failure or incomplete residual admission.
    pub fn borrow_inventory_once_v2<'query>(&'query mut self, index: usize,
        receiving: &ControllerInitialBrokerSessionReceivingV1, journal: &Journal,
        shape: crate::DeleteInventorySecurityShapeDataV1,
    ) -> Result<OperatorReconciliationInventoryLoanV2<'query, 'owner, 'controller, 'seed, 'completed>, ResourceReservationErrorV1> {
        self.require_current_v2()?;
        let context = self.inventory_context_v2(index)?;
        if !self.owner.inventory[..index].iter().all(InventoryOriginalsV1::is_completed_query_v2) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        RecoveryInventorySourceV2::Reconciliation { source: self, index, context }
            .begin_query_v2(receiving, journal, shape)
    }
}

pub(super) fn context_for_role_v2(role: Role, index: usize) -> Result<InventoryContextV2, ResourceReservationErrorV1> {
    let (protocol, method) = match (role, index) {
        (Role::Host, 0) => (BrokerSessionProtocolV1::Host, BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME),
        (Role::Network, 0) => (BrokerSessionProtocolV1::Network, BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES),
        (Role::Mount, 0) => (BrokerSessionProtocolV1::Mount, BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS),
        _ => return Err(ResourceReservationErrorV1::Conflict),
    };
    Ok(InventoryContextV2 { protocol, method, storage_recover: false, stop_cleanup: false,
        directory: crate::journal::controller_session_directory_data_v1(role.broker_role_data_v2()) })
}


fn maintenance_context_v2(index: usize) -> Result<InventoryContextV2, ResourceReservationErrorV1> {
    use crate::ControllerInitialBrokerSessionRoleV1 as Role;
    let (role, protocol, method) = match index {
        0 => (Role::Host, BrokerSessionProtocolV1::Host, BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME),
        1 => (Role::Mount, BrokerSessionProtocolV1::Mount, BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS),
        2 => (Role::Storage, BrokerSessionProtocolV1::Storage, BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES),
        3 => (Role::Network, BrokerSessionProtocolV1::Network, BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES),
        _ => return Err(ResourceReservationErrorV1::Conflict),
    };
    Ok(InventoryContextV2 { protocol, method, storage_recover: false, stop_cleanup: false,
        directory: crate::journal::controller_session_directory_data_v1(role) })
}

pub(in crate::controller_resource_reservation) fn maintenance_method_data_v2(index: usize)
    -> Result<(BrokerSessionProtocolV1, BrokerMethod), ResourceReservationErrorV1>
{
    maintenance_context_v2(index).map(|context| (context.protocol, context.method))
}

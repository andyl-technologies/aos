//! Joins one cold Recover or reconciliation Session to its actual C interval.
//!
//! The private fields split one complete requirement into the upper Recover
//! models and its simultaneously held Session. Both feed the existing single
//! C continuation ledger; this owner has no account, capacity or grant factory.

use super::*;
use std::sync::Mutex;
use aos_sandbox_core::component_receiving::operation_traffic_demand_v1;
use crate::controller_receiving::initial_session::{
    ControllerInitialSessionReceivingOriginalV1, ControllerInitialBrokerSessionRoleV1,
};

/// Selects one finite read-only reconciliation endpoint on the current successor.
///
/// This selector is DATA. Its actual parent Recover original supplies payment
/// and native affinity; protected recovery semantics remain with Domain.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerReconciliationInventoryRoleV2 {
    /// The current Host runtime and execution inventory.
    Host,
    /// The current Mount resources, acquisitions and destination slots.
    Mount,
    /// The current Network resources and namespace inventory.
    Network,
}

impl ControllerReconciliationInventoryRoleV2 {
    /// Returns only the corresponding fixed role as comparison DATA.
    #[must_use]
    pub const fn broker_role_data_v2(self) -> ControllerInitialBrokerSessionRoleV1 {
        match self {
            Self::Host => ControllerInitialBrokerSessionRoleV1::Host,
            Self::Mount => ControllerInitialBrokerSessionRoleV1::Mount,
            Self::Network => ControllerInitialBrokerSessionRoleV1::Network,
        }
    }
}

struct RepresentationDataV1 {
    active: bool,
    upper: ResourceVector,
    session: ResourceVector,
    physical_spent: ResourceVector,
    physical_pending: Option<ResourceVector>,
}

#[derive(Clone, Copy)]
enum SessionRepresentationFundingV3 {
    OperatorRecover,
    RecoveredOrdinary,
    ExecutionCold,
    StopCleanup,
}

pub(in crate::controller_receiving) struct ControllerSessionRepresentationV3 {
    funding: SessionRepresentationFundingV3,
    stop_cleanup: bool,
    execution: Option<Arc<super::super::ControllerExecutionColdSessionBudgetV2>>,
    role: ControllerInitialBrokerSessionRoleV1,
    original: Arc<ControllerReceivingOriginalV1>,
    base: ResourceVector,
    data: Mutex<RepresentationDataV1>,
    pair: ([u8; 16], [u8; 16]),
    node: [u8; 16],
}

/// Keeps the same Recover Session financial identity until its native graph drops.
///
/// Private construction is tied to the genuine initial receiver. This owner
/// supplies no request permission, outcome, currentness or refund.
#[doc(hidden)]
#[must_use = "retain this identity after the native Session fields"]
pub struct ControllerRecoverySessionRetentionV1 {
    _original: Arc<ControllerSessionRepresentationV3>,
}

/// Retains the actual fresh Stop22 identity until the native Session drops.
///
/// Private construction rejoins the initial receiver. No Host permission,
/// financial capacity or semantic completion can be extracted from it.
#[doc(hidden)]
#[must_use = "retain this identity after every actual native Session field"]
pub struct ControllerStopCleanupSessionRetentionV1 {
    _original: Arc<ControllerSessionRepresentationV3>,
}

/// Retains only the actual native Stop22 original's existing financial affinity.
///
/// This owns shares of the original Controller, writer and native-turn
/// identities. It cannot grant a request, restore a spent interval or prove
/// positive disposition. Its constructor and comparer require the genuine
/// current native Cleanup seed; no identity is created from DATA.
#[doc(hidden)]
pub struct ControllerStopCleanupSourceAffinityV1 {
    original: Arc<ControllerReceivingOriginalV1>,
    writer: Arc<ControllerWriterIdentityV1>,
    turn: Arc<std::sync::atomic::AtomicBool>,
    association: aos_sandbox_protocol::domain_ledger::resource_bank::RecoveredHostStopCleanupAssociationDataV1,
}

impl ControllerStopCleanupSourceAffinityV1 {
    /// Prices the finite Root, inventory proof and temporary affinity carriers.
    ///
    /// # Errors
    /// Refuses checked compiled-layout overflow; this grants no receiving.
    pub fn receiving_demand_v1() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }
}

impl ControllerSessionRepresentationV3 {
    pub(in crate::controller_receiving) fn role_data_v2(&self)
        -> ControllerInitialBrokerSessionRoleV1
    {
        self.role
    }

    pub(in crate::controller_receiving) fn demand_v1() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<ControllerRecoverySessionRetentionV1>()))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<ControllerStopCleanupSessionRetentionV1>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<std::sync::LockResult<
                std::sync::MutexGuard<'static, RepresentationDataV1>>>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    }

    fn raise_complete_native_v3(&self, complete: ResourceVector)
        -> Result<(), ControllerReceivingErrorV1>
    {
        match self.funding {
            SessionRepresentationFundingV3::OperatorRecover => self.original.raise_continuation_complete_v1(
                ContinuationReceivingPurposeV1::OperatorRecover, self.base, complete,
            ),
            SessionRepresentationFundingV3::StopCleanup => self.original.raise_continuation_complete_v1(
                ContinuationReceivingPurposeV1::RecoveredLifecycleStop, self.base, complete),
            SessionRepresentationFundingV3::RecoveredOrdinary =>
                self.original.raise_recovered_session_complete_v2(self.role, complete),
            SessionRepresentationFundingV3::ExecutionCold => self.execution.as_ref()
                .ok_or(ControllerReceivingErrorV1::Conflict)?.raise_complete_v2(complete),
        }
    }

    pub(super) fn from_recovered_ordinary_native_v2(
        native: &ControllerCreateProvisioningReceivingV1,
        profile: &ControllerSelfProfileOriginalV1,
        role: ControllerInitialBrokerSessionRoleV1,
        session_fixed: ResourceVector,
    ) -> Result<Self, ControllerBankLaunchErrorV1> {
        if native.purpose != ContinuationReceivingPurposeV1::RecoveredOrdinarySession(role) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let base = *native.entry.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        native.original.require_recovered_session_current_v2(role)?;
        let fixed = *native.fixed.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        let pair = native.profile.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .active_pair_data_v1(profile)?;
        let node = native.original.observed_enrollment_data_v1()?.identity.native_fields().node;
        Ok(Self {
            funding: SessionRepresentationFundingV3::RecoveredOrdinary,
            stop_cleanup: false,
            execution: None,
            role, original: Arc::clone(&native.original), base,
            data: Mutex::new(RepresentationDataV1 {
                active: true, upper: fixed.checked_add(Self::demand_v1()?)?, session: session_fixed,
                physical_spent: ResourceVector::ZERO, physical_pending: None,
            }), pair, node,
        })
    }

    pub(in crate::controller_receiving) fn is_reconciliation_v2(&self) -> bool {
        matches!(self.funding, SessionRepresentationFundingV3::OperatorRecover) && !self.stop_cleanup
    }

    pub(in crate::controller_receiving) fn is_stop_cleanup_v1(&self) -> bool {
        self.stop_cleanup && matches!(self.funding,
            SessionRepresentationFundingV3::OperatorRecover | SessionRepresentationFundingV3::StopCleanup)
            && self.role == ControllerInitialBrokerSessionRoleV1::Host
    }

    pub(in crate::controller_receiving) fn is_stop_cleanup_source_v1(&self) -> bool {
        matches!(self.funding, SessionRepresentationFundingV3::StopCleanup)
    }

    pub(in crate::controller_receiving) fn is_execution_cold_v2(&self) -> bool {
        matches!(self.funding, SessionRepresentationFundingV3::ExecutionCold)
    }

    pub(in crate::controller_receiving) fn from_execution_cold_v2(
        original: Arc<ControllerReceivingOriginalV1>,
        execution: Arc<super::super::ControllerExecutionColdSessionBudgetV2>,
        session: ResourceVector,
    ) -> Result<Self, ControllerBankLaunchErrorV1> {
        let pair = execution.pair_data_v2()?;
        let node = execution.node_data_v2()?;
        Ok(Self {
            funding: SessionRepresentationFundingV3::ExecutionCold, stop_cleanup: false, execution: Some(execution),
            role: ControllerInitialBrokerSessionRoleV1::Host, original, base: ResourceVector::ZERO,
            data: Mutex::new(RepresentationDataV1 {
                active: true, upper: Self::demand_v1()?.checked_add(
                    super::super::ControllerExecutionColdSessionBudgetV2::demand_v2()?)?, session,
                physical_spent: ResourceVector::ZERO, physical_pending: None,
            }), pair, node,
        })
    }

    pub(in crate::controller_receiving) fn matches_execution_cold_v2(&self,
        expected: &Arc<super::super::ControllerExecutionColdSessionBudgetV2>,
    ) -> bool {
        self.is_execution_cold_v2() && self.execution.as_ref()
            .is_some_and(|actual| Arc::ptr_eq(actual, expected))
    }

    pub(in crate::controller_receiving) fn retain_recovery_native_v1(this: &Arc<Self>)
        -> Result<Option<ControllerRecoverySessionRetentionV1>, ControllerReceivingErrorV1>
    {
        this.require_current_v1()?;
        Ok((matches!(this.funding, SessionRepresentationFundingV3::OperatorRecover)
            && this.role == ControllerInitialBrokerSessionRoleV1::Host)
            .then(|| ControllerRecoverySessionRetentionV1 { _original: Arc::clone(this) }))
    }

    pub(in crate::controller_receiving) fn retain_execution_native_v2(&self)
        -> Result<Option<super::super::ControllerExecutionColdSessionRetentionV2>, ControllerReceivingErrorV1>
    {
        self.require_current_v1()?;
        self.execution.as_ref().map(|actual|
            super::super::ControllerExecutionColdSessionBudgetV2::retain_native_v2(actual)).transpose()
    }

    pub(in crate::controller_receiving) fn retain_stop_cleanup_native_v1(this: &Arc<Self>)
        -> Result<Option<ControllerStopCleanupSessionRetentionV1>, ControllerReceivingErrorV1>
    {
        this.require_current_v1()?;
        Ok(this.is_stop_cleanup_source_v1().then(||
            ControllerStopCleanupSessionRetentionV1 { _original: Arc::clone(this) }))
    }

    pub(in crate::controller_receiving) fn require_current_v1(&self)
        -> Result<(), ControllerReceivingErrorV1>
    {
        if !self.data.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?.active {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        match self.funding {
            SessionRepresentationFundingV3::OperatorRecover =>
                self.original.require_operator_recover_session_current_v1(self.base),
            SessionRepresentationFundingV3::StopCleanup =>
                self.original.require_recovered_stop_session_current_v1(self.base),
            SessionRepresentationFundingV3::RecoveredOrdinary =>
                self.original.require_recovered_session_current_v2(self.role),
            SessionRepresentationFundingV3::ExecutionCold => self.execution.as_ref()
                .ok_or(ControllerReceivingErrorV1::Conflict)?.require_current_v2(),
        }
    }

    pub(in crate::controller_receiving) fn raise_session_v1(&self, complete: ResourceVector)
        -> Result<(), ControllerReceivingErrorV1>
    {
        self.require_current_v1()?;
        let mut data = self.data.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        let joined = data.upper.checked_add(complete)?.checked_add(data.physical_spent)?
            .checked_add(data.physical_pending.unwrap_or(ResourceVector::ZERO))?;
        self.raise_complete_native_v3(joined)?;
        data.session = complete;
        Ok(())
    }

    pub(in crate::controller_receiving) fn raise_physical_session_v1(
        &self, complete: ResourceVector, physical: ResourceVector,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !matches!(self.role, ControllerInitialBrokerSessionRoleV1::Storage
            | ControllerInitialBrokerSessionRoleV1::Mount) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.require_current_v1()?;
        let mut data = self.data.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        if data.physical_pending.is_some() { return Err(ControllerReceivingErrorV1::Conflict); }
        let traffic = operation_traffic_demand_v1(physical);
        let session = complete.checked_sub(traffic)?;
        let joined = data.upper.checked_add(session)?.checked_add(data.physical_spent)?
            .checked_add(traffic)?;
        self.raise_complete_native_v3(joined)?;
        data.session = session;
        data.physical_pending = Some(traffic);
        Ok(())
    }

    pub(in crate::controller_receiving) fn prepare_physical_operation_v1(
        &self, required: ResourceVector,
        destination: &mut Option<crate::receiving::ComponentReceivingOwnedOperationV1>,
    ) -> Result<(), ControllerReceivingErrorV1> {
        if !matches!(self.role, ControllerInitialBrokerSessionRoleV1::Storage
            | ControllerInitialBrokerSessionRoleV1::Mount) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.require_current_v1()?;
        let mut data = self.data.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        let traffic = operation_traffic_demand_v1(required);
        if data.physical_pending != Some(traffic) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        match self.funding {
            SessionRepresentationFundingV3::OperatorRecover =>
                self.original.prepare_operator_recover_physical_operation_v1(self.base, required, destination)?,
            SessionRepresentationFundingV3::RecoveredOrdinary =>
                self.original.prepare_recovered_session_physical_v2(self.role, required, destination)?,
            SessionRepresentationFundingV3::ExecutionCold | SessionRepresentationFundingV3::StopCleanup =>
                return Err(ControllerReceivingErrorV1::Conflict),
        }
        data.physical_spent = data.physical_spent.checked_add(traffic)?;
        data.physical_pending = None;
        Ok(())
    }

    pub(super) fn raise_upper_v1<P>(&self, native: &mut ControllerCreateProvisioningReceivingV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, complete: ResourceVector,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_current_v1()?;
        let mut data = self.data.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        let helper = Self::demand_v1()?;
        let upper = complete.checked_add(helper)?;
        native.require_complete_representation_inner_v1(writer, launch, profile,
            upper.checked_add(data.session)?.checked_add(data.physical_spent)?
                .checked_add(data.physical_pending.unwrap_or(ResourceVector::ZERO))?)?;
        data.upper = native.fixed.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?
            .checked_add(upper)?;
        Ok(())
    }

    pub(in crate::controller_receiving) fn pair_data_v1(&self)
        -> Result<([u8; 16], [u8; 16]), ControllerReceivingErrorV1>
    { self.require_current_v1()?; Ok(self.pair) }

    pub(in crate::controller_receiving) fn node_data_v1(&self)
        -> Result<[u8; 16], ControllerReceivingErrorV1>
    { self.require_current_v1()?; Ok(self.node) }

    pub(in crate::controller_receiving) fn fence_primary_v1(&self)
        -> Result<(), ControllerReceivingErrorV1>
    {
        let mut data = self.data.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
        data.active = false;
        Ok(())
    }

    pub(super) fn end_primary_v1(&self) {
        match self.data.lock() {
            Ok(mut data) => data.active = false,
            Err(_) => std::process::abort(),
        }
    }
}

impl ControllerOperatorRecoverReceivingV1 {
    /// Requires actual last-owner disposal of any entered cold Session graph.
    ///
    /// The final Session retains the same private representation identity after
    /// its journal/socket/checkpoint fields; the initial capture retains it too.
    /// The original amount remains charged and no native owner is recreated.
    ///
    /// # Errors
    /// Refuses a live capture/Session alias or pending physical operation.
    #[doc(hidden)]
    pub fn require_cold_session_retired_v1(&self) -> Result<(), ControllerReceivingErrorV1> {
        if !matches!(self.session_retired_before_posts, Some(Ok(()))) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.require_cold_session_last_owner_v1()?;
        if let Some(session) = &self.session {
            if session.data.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?.active {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
        }
        Ok(())
    }

    pub(super) fn require_cold_session_last_owner_v1(&self) -> Result<(), ControllerReceivingErrorV1> {
        if let Some(session) = &self.session {
            let data = session.data.try_lock().map_err(|_| ControllerReceivingErrorV1::Conflict)?;
            if data.physical_pending.is_some() || Arc::strong_count(session) != 1 {
                return Err(ControllerReceivingErrorV1::Conflict);
            }
        }
        Ok(())
    }

    /// Joins only this actual Recover's finite Host cleanup receiver.
    ///
    /// # Errors
    /// Refuses another private purpose, native original or closed interval.
    #[doc(hidden)]
    pub fn require_stop_cleanup_session_original_v1(&self,
        actual: &ControllerInitialSessionReceivingOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let expected = self.session.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?;
        if !expected.is_stop_cleanup_v1() || !actual.matches_recovery_session_original_v2(
            expected, &self.native.original, ControllerInitialBrokerSessionRoleV1::Host)
        { return Err(ControllerReceivingErrorV1::Conflict); }
        expected.require_current_v1()
    }

    /// Joins only this actual reconciliation role's native Session receiver.
    ///
    /// # Errors
    /// Refuses another role, original, initial claim or closed residual interval.
    #[doc(hidden)]
    pub fn require_reconciliation_inventory_session_original_v2(&self,
        actual: &ControllerInitialSessionReceivingOriginalV1,
        role: ControllerReconciliationInventoryRoleV2,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let expected = self.session.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?;
        if !expected.is_reconciliation_v2() { return Err(ControllerReceivingErrorV1::Conflict); }
        if !actual.matches_recovery_session_original_v2(expected, &self.native.original,
            role.broker_role_data_v2()) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        expected.require_current_v1()
    }

    /// Compares only the same genuine Recover Session receiver and original.
    ///
    /// # Errors
    /// Refuses a foreign initial/C23/Recover receiver or closed native interval.
    #[doc(hidden)]
    pub fn require_storage_session_original_v1(&self,
        actual: &ControllerInitialSessionReceivingOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let expected = self.session.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?;
        if !actual.matches_recover_storage_original_v1(expected, &self.native.original) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        expected.require_current_v1()
    }

    /// Starts the distinct cold Storage receiver under this actual Recover.
    ///
    /// The protected upper admission must retain its authorization and Source
    /// loan continuously. This mechanical receiver lends no recovery result or
    /// request permission and never claims an initial Session slot.
    ///
    /// # Errors
    /// Retains repeated entry, foreign current custody, representation refusal,
    /// or missing actual original enrollment/profile observations.
    #[doc(hidden)]
    pub fn begin_storage_session_receiving_once_v1<P>(&mut self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, session_fixed: ResourceVector,
    ) -> Result<ControllerInitialSessionReceivingOriginalV1, ControllerBankLaunchErrorV1> {
        self.begin_recovery_session_once_v2(writer, launch, profile,
            ControllerInitialBrokerSessionRoleV1::Storage, session_fixed, false)
    }

    /// Starts one paid read-only reconciliation Session on this actual successor.
    ///
    /// The whole original recovery authorization, Source cut and no-active
    /// semantic proof remain upper-owned. No initial role claim is reused.
    /// This method grants no query, mutation, enrollment or normal Ready state.
    ///
    /// # Errors
    /// Retains repeated entry, foreign current custody or complete source refusal.
    #[doc(hidden)]
    pub fn begin_reconciliation_inventory_session_once_v2<P>(&mut self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, role: ControllerReconciliationInventoryRoleV2,
        session_fixed: ResourceVector,
    ) -> Result<ControllerInitialSessionReceivingOriginalV1, ControllerBankLaunchErrorV1> {
        self.begin_recovery_session_once_v2(writer, launch, profile,
            role.broker_role_data_v2(), session_fixed, false)
    }

    /// Starts the finite financial Host cleanup Session on this actual Recover.
    ///
    /// This private marker grants neither query nor effect authority.
    ///
    /// # Errors
    /// Retains repeated entry, foreign custody, profile or same-payer refusal.
    #[doc(hidden)]
    pub fn begin_host_stop_cleanup_session_once_v1<P>(&mut self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, fixed: ResourceVector,
    ) -> Result<ControllerInitialSessionReceivingOriginalV1, ControllerBankLaunchErrorV1> {
        self.begin_recovery_session_once_v2(writer, launch, profile,
            ControllerInitialBrokerSessionRoleV1::Host, fixed, true)
    }

    fn begin_recovery_session_once_v2<P>(&mut self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, role: ControllerInitialBrokerSessionRoleV1,
        session_fixed: ResourceVector, stop_cleanup: bool,
    ) -> Result<ControllerInitialSessionReceivingOriginalV1, ControllerBankLaunchErrorV1> {
        if self.session_entry.is_some() || self.session.is_some() {
            let first = self.failure().is_none();
            self.session_reentry.get_or_insert(ControllerBankLaunchErrorV1::Conflict);
            self.session_reentry_primary |= first;
            if let Some(storage) = &self.session { storage.end_primary_v1(); }
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let earlier_native = self.native.failure().is_some();
        self.session_entry = Some((|| {
            self.require_current_v1(writer, launch, profile)?;
            let native = &mut self.native;
            let fixed = *native.fixed.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            let represented = match native.representation.as_ref() {
                Some(Ok(represented)) => *represented,
                Some(Err(_)) => return Err(ControllerBankLaunchErrorV1::Conflict),
                None => fixed.checked_add(native.initial_complete)?,
            };
            let upper = represented.checked_sub(fixed)?.checked_add(ControllerSessionRepresentationV3::demand_v1()?)?;
            native.require_complete_representation_v1(writer, launch, profile, upper.checked_add(session_fixed)?)?;
            let pair = native.profile.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
                .active_pair_data_v1(profile)?;
            let node = native.original.observed_enrollment_data_v1()?.identity.native_fields().node;
            let base = *native.entry.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            self.session = Some(Arc::new(ControllerSessionRepresentationV3 {
                funding: SessionRepresentationFundingV3::OperatorRecover,
                stop_cleanup,
                execution: None,
                role,
                original: Arc::clone(&native.original), base,
                data: Mutex::new(RepresentationDataV1 {
                    active: true, upper: fixed.checked_add(upper)?, session: session_fixed,
                    physical_spent: ResourceVector::ZERO, physical_pending: None,
                }), pair, node,
            }));
            Ok(())
        })());
        self.session_entry_primary = !earlier_native && self.session_entry.as_ref().is_some_and(Result::is_err);
        match (&self.session_entry, &self.session) {
            (Some(Ok(())), Some(storage)) => Ok(ControllerInitialSessionReceivingOriginalV1::from_recover_v1(
                Arc::clone(&self.native.original), profile, Arc::clone(storage),
            )),
            _ => Err(ControllerBankLaunchErrorV1::Conflict),
        }
    }
}

impl ControllerCreateProvisioningReceivingV1 {
    fn stop_cleanup_association_data_v1<P>(&self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<aos_sandbox_protocol::domain_ledger::resource_bank::RecoveredHostStopCleanupAssociationDataV1,
        ControllerBankLaunchErrorV1> {
        self.require_lifecycle_stop_current_v4(writer, launch, profile)?;
        if self.purpose != ContinuationReceivingPurposeV1::RecoveredLifecycleStop {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        match self.recovered_stop_intake_v3().ok_or(ControllerBankLaunchErrorV1::Conflict)?
            .stop_seed_record_data_v3(writer, launch, profile)? {
            aos_sandbox_protocol::domain_ledger::resource_bank::RecoveredStopSeedFundingDataV3::Cleanup(seed) =>
                Ok(seed.association),
            _ => Err(ControllerBankLaunchErrorV1::Conflict),
        }
    }

    /// Arms the fresh Source22 turn after the real seed-publication turnover.
    ///
    /// This records the SAME native turn identity only after its genuine
    /// Cleanup seed/currentness check. It precedes Source/cold/model growth.
    /// The initial seed-publication turn is never armed through this path.
    ///
    /// ```compile_fail
    /// use aos_sandbox_broker::controller_receiving::bank_launch::ControllerCreateProvisioningReceivingV1;
    /// fn fabricate(native: &mut ControllerCreateProvisioningReceivingV1) {
    ///     native.cleanup_source_scope = Some(std::sync::Arc::new(
    ///         std::sync::atomic::AtomicBool::new(false)));
    /// }
    /// ```
    ///
    /// # Errors
    /// Retains another seed, failed native turn or repeated scope entry.
    #[doc(hidden)]
    pub fn arm_stop_cleanup_source_turn_once_v1<P>(&mut self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.cleanup_source_scope_entry.is_some() || self.cleanup_source_scope.is_some() {
            self.cleanup_source_scope_reentry.get_or_insert(ControllerBankLaunchErrorV1::Conflict);
            self.first.get_or_insert(First::CleanupScope);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.cleanup_source_scope_entry = Some((|| {
            self.stop_cleanup_association_data_v1(writer, launch, profile)?;
            if self.cleanup_session.is_some() || self.cleanup_session_entry.is_some() {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            self.cleanup_source_scope = Some(Arc::clone(self.turn_identity.as_ref()
                .ok_or(ControllerBankLaunchErrorV1::Conflict)?));
            Ok(())
        })());
        if !matches!(self.cleanup_source_scope_entry, Some(Ok(()))) {
            self.first.get_or_insert(First::CleanupScope);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    fn require_stop_cleanup_source_scope_v1(&self) -> Result<(), ControllerBankLaunchErrorV1> {
        if !matches!(self.cleanup_source_scope_entry, Some(Ok(())))
            || !self.cleanup_source_scope.as_ref().is_some_and(|scope|
                self.turn_identity.as_ref().is_some_and(|turn| Arc::ptr_eq(scope, turn)))
        { return Err(ControllerBankLaunchErrorV1::Conflict); }
        Ok(())
    }

    /// Captures shares of this same genuine Stop22 original's native identities.
    ///
    /// # Errors
    /// Refuses another native purpose, failed seed or no longer current payer.
    #[doc(hidden)]
    pub fn capture_stop_cleanup_source_affinity_v1<P>(&self,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<ControllerStopCleanupSourceAffinityV1, ControllerBankLaunchErrorV1> {
        let association = self.stop_cleanup_association_data_v1(writer, launch, profile)?;
        self.require_stop_cleanup_source_scope_v1()?;
        Ok(ControllerStopCleanupSourceAffinityV1 {
            original: Arc::clone(&self.original), writer: Arc::clone(&self.identity),
            turn: Arc::clone(self.turn_identity.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?),
            association,
        })
    }

    /// Compares an actual retained affinity with this same current Stop22 turn.
    ///
    /// # Errors
    /// Refuses another original, writer, turn, Cleanup seed or ended receiver.
    #[doc(hidden)]
    pub fn require_stop_cleanup_source_affinity_v1<P>(&self,
        affinity: &ControllerStopCleanupSourceAffinityV1,
        writer: &ControllerCoordinatorWriterV1<P>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let association = self.stop_cleanup_association_data_v1(writer, launch, profile)?;
        self.require_stop_cleanup_source_scope_v1()?;
        if !Arc::ptr_eq(&affinity.original, &self.original)
            || !Arc::ptr_eq(&affinity.writer, &self.identity)
            || !self.turn_identity.as_ref().is_some_and(|turn| Arc::ptr_eq(turn, &affinity.turn))
            || affinity.association != association
        { return Err(ControllerBankLaunchErrorV1::Conflict); }
        Ok(())
    }

    /// Starts one Host Session on this actual fresh purpose22 Stop receiver.
    ///
    /// The existing same-ledger representation joins both resident upper and
    /// Session requirements. Its finite funding arm cannot select an ordinary
    /// Stop, old Recover17, Execution budget or initial-role claim.
    ///
    /// # Errors
    /// Retains another seed purpose, repeated entry, currentness or complete
    /// representation refusal. No native original is reconstructed on failure.
    #[doc(hidden)]
    pub fn begin_host_stop_cleanup_source_session_once_v1<P>(
        &mut self, writer: &ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        session_fixed: ResourceVector,
    ) -> Result<ControllerInitialSessionReceivingOriginalV1, ControllerBankLaunchErrorV1> {
        if self.cleanup_session_entry.is_some() || self.cleanup_session.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.cleanup_session_entry = Some((|| {
            self.require_lifecycle_stop_current_v4(writer, launch, profile)?;
            self.require_stop_cleanup_source_scope_v1()?;
            if self.purpose != ContinuationReceivingPurposeV1::RecoveredLifecycleStop {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            let seed = self.recovered_stop_intake_v3().ok_or(ControllerBankLaunchErrorV1::Conflict)?
                .stop_seed_record_data_v3(writer, launch, profile)?;
            if !matches!(seed, aos_sandbox_protocol::domain_ledger::resource_bank::RecoveredStopSeedFundingDataV3::Cleanup(_)) {
                return Err(ControllerBankLaunchErrorV1::Conflict);
            }
            let fixed = *self.fixed.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            let represented = match self.representation.as_ref() {
                Some(Ok(complete)) => *complete,
                Some(Err(_)) => return Err(ControllerBankLaunchErrorV1::Conflict),
                None => fixed.checked_add(self.initial_complete)?,
            };
            let upper = represented.checked_sub(fixed)?
                .checked_add(ControllerSessionRepresentationV3::demand_v1()?)?;
            self.require_complete_representation_inner_v1(writer, launch, profile,
                upper.checked_add(session_fixed)?)?;
            let pair = self.profile.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
                .active_pair_data_v1(profile)?;
            let node = self.original.observed_enrollment_data_v1()?.identity.native_fields().node;
            let base = *self.entry.as_ref().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
            self.cleanup_session = Some(Arc::new(ControllerSessionRepresentationV3 {
                funding: SessionRepresentationFundingV3::StopCleanup, stop_cleanup: true,
                execution: None, role: ControllerInitialBrokerSessionRoleV1::Host,
                original: Arc::clone(&self.original), base,
                data: Mutex::new(RepresentationDataV1 {
                    active: true, upper: fixed.checked_add(upper)?, session: session_fixed,
                    physical_spent: ResourceVector::ZERO, physical_pending: None,
                }), pair, node,
            }));
            Ok(())
        })());
        if !matches!(self.cleanup_session_entry, Some(Ok(()))) {
            self.first.get_or_insert(First::SessionEntry);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let actual = self.cleanup_session.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ControllerInitialSessionReceivingOriginalV1::from_recover_v1(
            Arc::clone(&self.original), profile, Arc::clone(actual)))
    }

    /// Rejoins only the real initial receiver of this same Source22 interval.
    ///
    /// # Errors
    /// Refuses another finite purpose, native original, Session or ended payer.
    #[doc(hidden)]
    pub fn require_stop_cleanup_source_session_original_v1(&self,
        actual: &ControllerInitialSessionReceivingOriginalV1,
    ) -> Result<(), ControllerReceivingErrorV1> {
        let expected = self.cleanup_session.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?;
        if !expected.is_stop_cleanup_source_v1()
            || !actual.matches_recovery_session_original_v2(expected, &self.original,
                ControllerInitialBrokerSessionRoleV1::Host)
        { return Err(ControllerReceivingErrorV1::Conflict); }
        expected.require_current_v1()
    }

    pub(crate) fn require_stop_cleanup_session_disposal_v1(&self)
        -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_stop_cleanup_session_graph_retired_v1()?;
        if self.cleanup_source_scope.is_some() && !self.finished {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn require_stop_cleanup_session_graph_retired_v1(&self)
        -> Result<(), ControllerBankLaunchErrorV1> {
        if self.cleanup_source_scope.is_some() {
            self.require_stop_cleanup_source_scope_v1()?;
        } else if self.cleanup_session.is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let Some(session) = self.cleanup_session.as_ref() else { return Ok(()); };
        let data = session.data.try_lock().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        if !matches!(self.cleanup_session_fence, Some(Ok(())))
            || !session.is_stop_cleanup_source_v1() || Arc::strong_count(session) != 1
            || data.active || data.physical_pending.is_some()
        { return Err(ControllerBankLaunchErrorV1::Conflict); }
        Ok(())
    }

    /// Completes the same parked Stop22 continuation after actual native Drop.
    ///
    /// Every owed Controller/name/profile/launch post has already completed.
    /// This final bookkeeping stage samples no clock and issues no work. Its
    /// actual last-owner check precedes the original ledger and name disposal.
    ///
    /// # Errors
    /// Refuses incomplete/failed posts, a foreign writer/profile/launch, live
    /// Session/cold graph, another purpose, reentry or original ledger refusal.
    #[doc(hidden)]
    pub fn complete_stop_cleanup_native_after_disposal_v1<P>(
        &mut self, writer: &mut ControllerCoordinatorWriterV1<P>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if !self.cleanup_posts_complete || self.cleanup_source_scope.is_none() || self.cleanup_graph_retired.is_some()
            || self.finished || self.first.is_some() || self.finish_result.is_some()
            || !self.same_writer(writer)
        { return Err(ControllerBankLaunchErrorV1::Conflict); }
        self.cleanup_graph_retired = Some((|| {
            self.require_stop_cleanup_session_graph_retired_v1()?;
            self.profile.as_ref().ok_or(ControllerBankLaunchErrorV1::Conflict)?
                .require_completed_v1(profile)?;
            launch.require_controller_baseline_precharge_v1(writer)
        })());
        if !matches!(self.cleanup_graph_retired, Some(Ok(()))) {
            self.first.get_or_insert(First::SessionGraph);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.complete_native_disposal_v1(writer)
    }
}

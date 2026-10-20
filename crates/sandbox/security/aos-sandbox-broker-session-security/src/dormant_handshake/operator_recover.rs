//! Uses one cold capture owner for closed Storage Recover and reconciliation.
//!
//! Actual lower provenance selects payment. Reconciliation may use an ordinary
//! role history only when its existing terminal-head initialization accepts it;
//! an interrupted prior request remains untouched and unavailable.

mod session_open;

use super::*;
use aos_sandbox_controller_domain::{ControllerInitialBrokerSessionRoleV1 as Role,
    OperatorCreateRecoveryLoanV1, OperatorReconciliationObservationLoanV2,
    OperatorStopCleanupObservationLoanV1,
    ResourceReservationErrorV1};
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};
use session_open::RecoverColdSessionOpenV2;

/// Retains one fresh Source/C18-funded NoApply cold Session and native capture.
///
/// This financial cold entry chooses only the signed42/43 profile. Root
/// acquisition, current public recovery authority and all effect gates remain
/// independently required by the subsequent concrete SDK borrower.
#[doc(hidden)]
#[derive(Default)]
#[must_use = "retain the whole cold capture until its final native disposal"]
pub struct ExecutionNoApplySessionOpenV2(RecoverColdSessionOpenV2);

impl ExecutionNoApplySessionOpenV2 {
    /// Opens the same fixed cold engine from the genuine fresh Source loan.
    ///
    /// # Errors
    /// Retains financial, current clock, native handshake and owed post errors.
    pub fn open_once_v2(&mut self,
        source: &mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionCleanupSourceLoanV2<'_, '_>,
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        controller: &mut aos_sandbox_controller_domain::Journal,
        profile: &std::sync::Arc<aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1>,
        image: crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.open_once_v2(ColdLoanV2::NoApply { source, bank, controller, profile }, image)
    }

    /// Moves the actual positively completed native Session once.
    #[must_use]
    pub fn take_completed_once_v2(&mut self) -> Option<DormantAuthenticatedBrokerSessionV1> {
        self.0.take_completed_once_v1()
    }

    /// Borrows the existing NoApply SDK after the exact Source/receiver join.
    ///
    /// The capture, Session native graph and fresh Source loan remain borrowed
    /// through the returned SDK loan. No ordinary or Recover receiver matches.
    ///
    /// # Errors
    /// Retains another financial original, incomplete cold capture, schema,
    /// protected history, actual target or SDK/native preparation refusal.
    pub fn borrow_cleanup_execution_no_apply_client_once_v2<'turn, 'scope, 'owner>(
        &'turn self, session: &'turn mut DormantAuthenticatedBrokerSessionV1,
        source: &'turn mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionCleanupSourceLoanV2<'scope, 'owner>,
        original: &'turn mut crate::HostExecutionNoApplySessionIoOriginalV2,
        native: &'turn mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionNoApplyOriginalV2,
        controller: &'turn mut aos_sandbox_controller_domain::Journal,
        bank: &'turn aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        profile: &'turn aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<crate::HostExecutionNoApplyClientSessionBorrowV2<'turn, 'turn, 'owner>,
        crate::controller_composition::OutputPreparationClosedV1>
    {
        let completed = self.0.borrow_completed_kernel_session_v1(&mut session.0)
            .map_err(|_| crate::controller_composition::OutputPreparationClosedV1)?;
        let (receiving, host) = completed.into_parts_v2();
        source.require_cold_session_original_v2(receiving)
            .map_err(|_| crate::controller_composition::OutputPreparationClosedV1)?;
        original.borrow_cleanup_once_v2(host, source, native, controller, bank, profile)
    }

    /// Borrows the retained native/SDK cause without further entry.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> { self.0.failure_v1() }
}

enum ColdLoanV2<'loan, 'owner, 'controller, 'seed, 'completed, 'cleanup_scope, 'cleanup_owner, 'stop_owner, 'stop_source> {
    Storage(&'loan mut OperatorCreateRecoveryLoanV1<'owner, 'controller>),
    StopCleanup(&'loan mut OperatorStopCleanupObservationLoanV1<'owner, 'controller>),
    Reconciliation(&'loan mut OperatorReconciliationObservationLoanV2<'owner, 'seed, 'completed, 'controller>),
    StopSource {
        source: &'loan mut aos_sandbox_controller_domain::controller_lifecycle_stop::ControllerHostStopCleanupSourceLoanV1<'stop_owner, 'stop_source>,
        controller: &'loan aos_sandbox_controller_domain::Journal,
    },
    NoApply {
        source: &'loan mut aos_sandbox_controller_domain::controller_execution_operation::ControllerExecutionCleanupSourceLoanV2<'cleanup_scope, 'cleanup_owner>,
        bank: &'loan aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        controller: &'loan mut aos_sandbox_controller_domain::Journal,
        profile: &'loan std::sync::Arc<aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1>,
    },
}

impl ColdLoanV2<'_, '_, '_, '_, '_, '_, '_, '_, '_> {
    fn role_v2(&self) -> Role {
        match self {
            Self::Storage(_) => Role::Storage,
            Self::StopCleanup(_) => Role::Host,
            Self::Reconciliation(loan) => loan.role_v2().broker_role_data_v2(),
            Self::NoApply { .. } | Self::StopSource { .. } => Role::Host,
        }
    }

    fn reserve_additional_v2(&mut self, demand: ResourceVector) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Storage(loan) => loan.reserve_additional_v1(demand),
            Self::StopCleanup(loan) => loan.reserve_additional_v1(demand),
            Self::Reconciliation(loan) => loan.reserve_additional_v2(demand),
            Self::StopSource { source, controller } => source.reserve_additional_v1(controller, demand),
            Self::NoApply { source, bank, controller, profile } => source.admit_stage_v2(
                bank, controller, profile, aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(demand)),
        }
    }

    fn check_frontier_v2(&mut self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        match self {
            Self::Storage(loan) => loan.check_frontier_v1(),
            Self::StopCleanup(loan) => loan.check_frontier_v1(),
            Self::Reconciliation(loan) => loan.check_frontier_v2(),
            Self::StopSource { source, controller } => source.check_frontier_v1(controller),
            Self::NoApply { source, bank, controller, profile } => source.check_cold_frontier_v2(bank, controller, profile),
        }
    }

    fn prepare_session_once_v2(&mut self, shape: aos_sandbox_controller_domain::ControllerInitialBrokerSessionShapeV1)
        -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Storage(loan) => loan.prepare_storage_session_once_v1(shape),
            Self::StopCleanup(loan) => loan.prepare_session_once_v1(shape),
            Self::Reconciliation(loan) => loan.prepare_session_once_v2(shape),
            Self::StopSource { source, controller } => source.prepare_cold_session_once_v1(controller, shape),
            Self::NoApply { source, bank, controller, profile } => source.prepare_cold_session_once_v2(
                bank, controller, std::sync::Arc::clone(profile), shape),
        }
    }

    fn take_session_receiver_once_v2(&mut self)
        -> Result<aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingV1, ResourceReservationErrorV1> {
        match self {
            Self::Storage(loan) => loan.take_storage_session_receiver_once_v1(),
            Self::StopCleanup(loan) => loan.take_session_receiver_once_v1(),
            Self::Reconciliation(loan) => loan.take_session_receiver_once_v2(),
            Self::StopSource { source, controller } => source.take_cold_receiver_once_v1(controller),
            Self::NoApply { source, .. } => source.take_cold_session_receiver_once_v2(),
        }
    }

    fn retain_sdk_refusal_once_v2(&mut self) {
        match self {
            Self::Storage(loan) => loan.retain_storage_sdk_refusal_once_v1(),
            Self::StopCleanup(loan) => loan.retain_sdk_refusal_once_v1(),
            Self::Reconciliation(loan) => loan.retain_sdk_refusal_once_v2(),
            Self::StopSource { source, .. } => source.retain_cold_sdk_refusal_v1(),
            Self::NoApply { source, .. } => source.retain_cold_sdk_refusal_v2(),
        }
    }

    fn observe_owed_clock_after_once_v2(&mut self) -> Result<RawPairedClockSample, ResourceReservationErrorV1> {
        match self {
            Self::Storage(loan) => loan.observe_owed_clock_after_once_v1(),
            Self::StopCleanup(loan) => loan.observe_owed_clock_after_once_v1(),
            Self::Reconciliation(loan) => loan.observe_owed_clock_after_once_v2(),
            Self::StopSource { source, controller } => source.owed_clock_after_v1(controller),
            Self::NoApply { source, .. } => source.observe_cold_owed_clock_after_v2(),
        }
    }
}

/// Retains the exact Host cleanup cold capture under an actual kind-2 Recover.
///
/// Opening this Session pays observation only. Fresh Stop effects still require
/// a distinct current purpose-22 owner, Root456 and native target ownership.
#[doc(hidden)]
#[derive(Default)]
#[must_use = "retain this whole cold capture with its genuine Recover owner"]
pub struct OperatorStopCleanupSessionOpenV1(RecoverColdSessionOpenV2);

impl OperatorStopCleanupSessionOpenV1 {
    /// Opens the exact signed 1/3 profile through the shared cold engine.
    ///
    /// # Errors
    /// Retains currentness, payment, clock, native and independently owed post
    /// refusals on the same actual Source/Controller interval.
    pub fn open_once_v1(&mut self, loan: &mut OperatorStopCleanupObservationLoanV1<'_, '_>,
        image: crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.open_once_v2(ColdLoanV2::StopCleanup(loan), image)
    }

    /// Moves the same positively completed Session with its protected history.
    #[must_use]
    pub fn take_completed_once_v1(&mut self) -> Option<DormantAuthenticatedBrokerSessionV1> {
        self.0.take_completed_once_v1()
    }

    pub(super) fn borrow_completed_kernel_session_v1<'held>(&'held self,
        session: &'held mut handshake::DormantAuthenticatedBrokerSessionV1,
    ) -> Result<handshake::ControllerInitialSessionCompletedBorrowV1<'held>, BrokerSessionSecurityError> {
        self.0.borrow_completed_kernel_session_v1(session)
    }

    /// Borrows the actual first refusal while retaining its entire prefix.
    pub fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.failure_v1()
    }
}

/// Retains the actual Storage Recover cold owner through the common engine.
#[doc(hidden)]
#[derive(Default)]
#[must_use = "retain the whole original through its independently owed posts"]
pub struct OperatorRecoverStorageSessionOpenV1(RecoverColdSessionOpenV2);

impl OperatorRecoverStorageSessionOpenV1 {
    /// Opens only the genuine Inventory18 Recover endpoint once.
    ///
    /// # Errors
    /// Retains funding, original-clock, cold/native and independent after errors.
    pub fn open_once_v1(&mut self, loan: &mut OperatorCreateRecoveryLoanV1<'_, '_>,
        image: crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.open_once_v2(ColdLoanV2::Storage(loan), image)
    }

    /// Moves the same positively completed outer Session once.
    #[must_use]
    pub fn take_completed_once_v1(&mut self) -> Option<DormantAuthenticatedBrokerSessionV1> {
        self.0.take_completed_once_v1()
    }

    pub(super) fn borrow_completed_kernel_session_v1<'held>(&'held self,
        session: &'held mut handshake::DormantAuthenticatedBrokerSessionV1,
    ) -> Result<handshake::ControllerInitialSessionCompletedBorrowV1<'held>, BrokerSessionSecurityError> {
        self.0.borrow_completed_kernel_session_v1(session)
    }

    /// Borrows the precise original cause without releasing its custody.
    pub fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> { self.0.failure_v1() }
}

/// Retains one newly paid read-only Host, Mount or Network cold capture.
///
/// Initial role claims and interrupted ordinary heads cannot construct this
/// owner. Its actual lender supplies the original Recover cutoff and role.
#[doc(hidden)]
#[derive(Default)]
#[must_use = "retain the whole original beside its same native interval"]
pub struct OperatorReconciliationSessionOpenV2(RecoverColdSessionOpenV2);

impl OperatorReconciliationSessionOpenV2 {
    /// Enters the finite endpoint under its new actual residual interval.
    ///
    /// # Errors
    /// Retains expired original authorization, payment, old nonterminal head,
    /// full replay, native capture and independently owed post refusals.
    pub fn open_once_v2(&mut self, loan: &mut OperatorReconciliationObservationLoanV2<'_, '_, '_, '_>,
        image: crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.open_once_v2(ColdLoanV2::Reconciliation(loan), image)
    }

    /// Moves the actual completed Session, preserving its full protected history.
    #[must_use]
    pub fn take_completed_once_v2(&mut self) -> Option<DormantAuthenticatedBrokerSessionV1> {
        self.0.take_completed_once_v1()
    }

    pub(super) fn borrow_completed_kernel_session_v2<'held>(&'held self,
        session: &'held mut handshake::DormantAuthenticatedBrokerSessionV1,
    ) -> Result<handshake::ControllerInitialSessionCompletedBorrowV1<'held>, BrokerSessionSecurityError> {
        self.0.borrow_completed_kernel_session_v1(session)
    }

    /// Borrows the actual first cold/native failure without replacing it.
    pub fn failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> { self.0.failure_v1() }
}

/// Holds the shared cold engine funded by the actual fresh purpose22 Source.
///
/// This distinct owner accepts no completed17 loan or old Session. Its real
/// lower marker selects only Host1/3 and retains the same Source22 native graph.
#[doc(hidden)]
#[derive(Default)]
#[must_use = "retain the whole cold graph until genuine Source22 disposal"]
pub struct OperatorStopCleanupSourceSessionOpenV1(RecoverColdSessionOpenV2);

impl OperatorStopCleanupSourceSessionOpenV1 {
    /// Opens the same fixed cold recipe under the actual fresh Source22.
    ///
    /// # Errors
    /// Retains payment, original-currentness, native/cold and owed-post failures.
    pub fn open_once_v1(
        &mut self,
        source: &mut aos_sandbox_controller_domain::controller_lifecycle_stop::ControllerHostStopCleanupSourceLoanV1<'_, '_>,
        controller: &aos_sandbox_controller_domain::Journal,
        image: crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.open_once_v2(ColdLoanV2::StopSource { source, controller }, image)
    }

    /// Moves only the genuine completed Source22 Session once.
    #[must_use]
    pub fn take_completed_once_v1(&mut self) -> Option<DormantAuthenticatedBrokerSessionV1> {
        self.0.take_completed_once_v1()
    }

    pub(super) fn borrow_completed_kernel_session_v1<'held>(
        &'held self,
        session: &'held mut handshake::DormantAuthenticatedBrokerSessionV1,
    ) -> Result<handshake::ControllerInitialSessionCompletedBorrowV1<'held>, BrokerSessionSecurityError> {
        self.0.borrow_completed_kernel_session_v1(session)
    }

    /// Borrows the actual first retained cold failure without reentry.
    pub fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.failure_v1()
    }
}

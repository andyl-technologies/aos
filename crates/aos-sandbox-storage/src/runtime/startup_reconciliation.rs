//! One startup reconciliation schedule for ordinary and genuine State callers.
//!
//! Native errors and transaction uncertainty remain on Runtime through both
//! independent State posts. Pure request/plan scratch keeps consuming lifetime.

use super::*;
use crate::state::encoding::StateEncodingLoanV1;

pub(super) struct StartupReconciliationOriginalV1 {
    pub(super) transactions: transaction_recovery::TransactionRecoveryOriginalV1,
    pub(super) catalog: inventory_catalog::InventoryCatalogOriginalV1,
    model: Option<Result<(), StorageBrokerError>>,
    pub(super) capacity: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    pub(super) arithmetic: Option<aos_sandbox_core::AccountingError>,
    pub(super) prepare_policy_read: crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1,
    worker_error: Option<ZfsWorkerError>,
    issuance_error: Option<crate::native_issuance::StorageNativeIssuanceErrorV1>,
    helper_error: Option<crate::helper::ZfsHelperError>,
    pub(super) pin_ensure_result: Option<Result<crate::pin_worker::WorkspacePinWorkerResultV1, ZfsWorkerError>>,
    pub(super) pin_remove_result: Option<Result<crate::pin_worker::WorkspacePinWorkerResultV1, ZfsWorkerError>>,
    application_error: Option<crate::DormantStorageBrokerCallErrorV1>,
    operator_retirement_error: Option<crate::helper::ZfsHelperError>,
    pub(super) operation_error: Option<crate::helper::ZfsHelperError>,
    pub(super) operator_policy_error: Option<StorageRuntimeError>,
    result: Option<Result<StorageRuntimeReadiness, StorageRuntimeError>>,
    post: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    entered: bool,
    pub(super) preparation_complete: bool,
}

impl StartupReconciliationOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            transactions: transaction_recovery::TransactionRecoveryOriginalV1::new(),
            catalog: inventory_catalog::InventoryCatalogOriginalV1::default(),
            model: None,
            capacity: None,
            arithmetic: None,
            prepare_policy_read: crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1::new(),
            worker_error: None,
            issuance_error: None,
            helper_error: None,
            pin_ensure_result: None,
            pin_remove_result: None,
            application_error: None,
            operator_retirement_error: None,
            operation_error: None,
            operator_policy_error: None,
            result: None,
            post: None,
            entered: false,
            preparation_complete: false,
        }
    }

    pub(super) fn helper_result_v1<T>(
        &mut self,
        result: Result<T, crate::helper::ZfsHelperError>,
        selected: bool,
    ) -> Result<T, StorageRuntimeError> {
        project_helper_result_v1(result, selected, &mut self.helper_error)
    }

    pub(super) fn worker_result_v1<T>(&mut self, result: Result<T, ZfsWorkerError>, selected: bool)
        -> Result<T, StorageRuntimeError>
    {
        result.map_err(|error| {
            if selected {
                self.worker_error = Some(error);
            }
            StorageRuntimeError::Recovery
        })
    }

    pub(super) fn operation_result_v1<T>(
        &mut self,
        result: Result<T, crate::helper::ZfsHelperError>,
        selected: bool,
    ) -> Result<T, StorageRuntimeError> {
        project_helper_result_v1(result, selected, &mut self.operation_error)
    }

    pub(super) fn failure<'a>(
        &'a self,
        coordinator: &'a StorageAdmissionCoordinator,
        helper: &'a StorageMutationHelper<Box<dyn ZfsProcessBackend + Send>>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        self.failure_with_guest_root_v2(coordinator, helper, None)
    }

    pub(super) fn failure_with_guest_root_v2<'a>(
        &'a self,
        coordinator: &'a StorageAdmissionCoordinator,
        helper: &'a StorageMutationHelper<Box<dyn ZfsProcessBackend + Send>>,
        guest_root: Option<&'a (dyn std::error::Error + 'static)>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        self.model.as_ref().and_then(|result| result.as_ref().err()).map(|cause| {
                if matches!(cause, StorageBrokerError::State(StorageStateError::Receiving)) {
                    coordinator.recovery_receiving_failure_v1().unwrap_or(cause as &dyn std::error::Error)
                } else { cause as &dyn std::error::Error }
            })
            .or_else(|| self.arithmetic.as_ref().map(|cause| cause as _))
            .or_else(|| self.capacity.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.prepare_policy_read.failure())
            .or_else(|| self.operation_error.as_ref().map(|cause|
                transaction_recovery::resolve_helper_failure(cause, coordinator, helper)))
            .or_else(|| self.operator_retirement_error.as_ref().map(|cause|
                transaction_recovery::resolve_helper_failure(cause, coordinator, helper)))
            .or_else(|| self.issuance_error.as_ref().map(|cause| cause as _))
            .or_else(|| self.transactions.failure(coordinator, helper))
            .or_else(|| self.worker_error.as_ref().map(|cause| match cause.physical_native_refusal_v1() {
                Some(marker) => marker as &dyn std::error::Error,
                None => cause as &dyn std::error::Error,
            }))
            .or_else(|| self.pin_remove_result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.pin_ensure_result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.helper_error.as_ref().map(|cause|
                transaction_recovery::resolve_helper_failure(cause, coordinator, helper)))
            .or_else(|| self.catalog.failure())
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| {
                if matches!(cause, StorageRuntimeError::Admission(StorageBrokerError::State(StorageStateError::Receiving))) {
                    coordinator.recovery_receiving_failure_v1().unwrap_or(cause as &dyn std::error::Error)
                } else { cause as &dyn std::error::Error }
            }))
            .or(guest_root)
            .or_else(|| self.application_error.as_ref().map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.post.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }
}

// Startup and recurring work retain distinct owners but share the same
// ordinary classification and selected whole-cause disposition.
fn project_helper_result_v1<T>(
    result: Result<T, crate::helper::ZfsHelperError>,
    selected: bool,
    destination: &mut Option<crate::helper::ZfsHelperError>,
) -> Result<T, StorageRuntimeError> {
    result.map_err(|cause| {
        if selected {
            *destination = Some(cause);
        }
        StorageRuntimeError::Recovery
    })
}

#[derive(Clone, Copy)]
enum InitialStatePurposeV1 {
    Direct,
    DeferredOperator,
}

struct ReconciliationPartsV1<'runtime> {
    coordinator: &'runtime mut StorageAdmissionCoordinator,
    helper: &'runtime mut StorageMutationHelper<Box<dyn ZfsProcessBackend + Send>>,
    pin_io: &'runtime mut (dyn WorkspacePinRuntimeIo + Send),
    pin_contract: &'runtime ZfsHelperContract,
    native_issuance: &'runtime mut Option<StorageNativeIssuanceLedgerV1>,
    workspaces: &'runtime mut Option<ValidatedPendingStorageWorkspaceCatalogV1>,
    worker_dispatch: &'runtime RepairWorkerDispatchGate,
    configuration_binding: ObjectDigest,
    broker_instance_id: [u8; 16],
    operator_startup: Option<&'runtime operator_startup::DeferredOperatorStartupV4>,
    readiness: &'runtime mut StorageRuntimeReadiness,
    resolver_policies: &'runtime mut Option<ProtectedStorageResolverPolicyDirectoryV1>,
    prepare_readiness: &'runtime mut StoragePrepareReadiness,
    policy_directory_original: &'runtime mut crate::resolver::protected_catalog::ResolverPolicyDirectoryOriginalV1,
    policy_read_original: &'runtime mut crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1,
}

impl ReconciliationPartsV1<'_> {
    fn run_paid_v1(
        &mut self,
        original: &mut StartupReconciliationOriginalV1,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
        prelude: Option<&operator_startup::DeferredOperatorStartupV4>,
    ) -> Result<StorageRuntimeReadiness, StorageRuntimeError> {
        self.prepare_paid_models_v1(original, receiving);
        if matches!(original.model, Some(Ok(()))) && matches!(original.capacity, Some(Ok(()))) {
            original.result = Some(self.run(original, Some(receiving), prelude));
        }
        // Both initial and recurring State intervals owe these observations
        // after every entered model, append, worker and publication result.
        original.post = Some(self.coordinator.finish_recovery_posts_v1(receiving));
        let Some(Ok(readiness)) = original.result.as_ref() else {
            return Err(StorageRuntimeError::Receiving);
        };
        if !matches!(original.post, Some(Ok(()))) {
            return Err(StorageRuntimeError::Receiving);
        }
        Ok(*readiness)
    }

    fn prepare_paid_models_v1(
        &mut self,
        original: &mut StartupReconciliationOriginalV1,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) {
        original.model = Some(self.coordinator.prepare_recovery_models_v1(receiving));
        if matches!(original.model, Some(Ok(()))) {
            original.capacity = Some(match inventory_catalog::InventoryCatalogOriginalV1::fixed_demand_v1()
                .and_then(|demand| {
                    use aos_sandbox_core::{AccountingError, ResourceDimension as D};
                    usize::try_from(demand.get(D::MemoryBytes)).ok()
                        .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<StartupReconciliationOriginalV1>()))
                        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<
                            crate::dormant_broker_session::DormantStorageLifecycleDisposalV1<'_, '_, '_, '_>,
                        >()))
                        .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })
                })
            {
                Ok(bytes) => receiving.reserve_encoded_capacity_v1(bytes, 0),
                Err(cause) => {
                    original.arithmetic = Some(cause);
                    Err(aos_sandbox::StorageReceivingClosedV1)
                }
            });
        }
    }

    fn run(
        &mut self,
        original: &mut StartupReconciliationOriginalV1,
        mut receiving: Option<&mut StateEncodingLoanV1<'_, '_>>,
        prelude: Option<&operator_startup::DeferredOperatorStartupV4>,
    ) -> Result<StorageRuntimeReadiness, StorageRuntimeError> {
        let selected = receiving.is_some();
        if let Some(startup) = prelude {
            let receiving = receiving.as_deref_mut().ok_or(StorageRuntimeError::Receiving)?;
            let plan = operator_startup::resume_operator_prelude_v1(
                self.coordinator, self.resolver_policies, self.prepare_readiness, startup,
                Some((self.policy_directory_original, self.policy_read_original)),
                Some((receiving, &mut original.operator_retirement_error)),
            )?;
            self.workspaces.as_mut().ok_or(StorageRuntimeError::Recovery)?.revalidate_plan(plan)?;
        }
        let _dispatch = self
            .worker_dispatch
            .enter()
            .map_err(|_| StorageRuntimeError::Recovery)?;
        if let Some(issuance) = self.native_issuance.as_mut() {
            issuance.validate_active_holds(self.coordinator).map_err(|cause| {
                if selected {
                    original.issuance_error = Some(cause);
                }
                StorageRuntimeError::Recovery
            })?;
            // Recovery must not publish a pending ReleaseHold around an active
            // interest, even when observation reports that the effect already
            // happened. Cleanup/recovery remains closed until both owners can
            // settle the exact original acceptance; journal replay is no bypass.
            for entry in self
                .coordinator
                .recovery_entries()
                .map_err(|_| StorageRuntimeError::Recovery)?
            {
                if !matches!(
                    entry.phase(),
                    DurableStoragePhase::Committed | DurableStoragePhase::Aborted
                ) {
                    let catalog = self
                        .coordinator
                        .recovery_catalog_for_native_interest(entry)
                        .map_err(|_| StorageRuntimeError::Recovery)?;
                    issuance.check_release(catalog.plan()).map_err(|cause| {
                        if selected {
                    original.issuance_error = Some(cause);
                }
                        StorageRuntimeError::Recovery
                    })?;
                }
            }
        }
        let mut pending = match receiving.as_deref_mut() {
            Some(receiving) => original.transactions.run(self.coordinator, self.helper, Some(receiving))?,
            None => reconcile_transaction_recovery(self.coordinator, self.helper)?,
        };
        for dispatch in self
            .coordinator
            .workspace_pin_observation_dispatches()
            .map_err(|_| StorageRuntimeError::Recovery)?
        {
            let request = match receiving.as_deref_mut() {
                Some(receiving) => dispatch.request_bytes_receiving_v1(self.pin_contract, receiving),
                None => dispatch.request_bytes(self.pin_contract),
            };
            let request = original.helper_result_v1(request, selected)?;
            let result = if let Some(receiving) = receiving.as_deref_mut() {
                reserve_pin_result_v1(receiving)?;
                let cutoff = worker_cutoff_v1()?;
                let mut stage = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::state(
                    receiving, self.coordinator.recovery_encoding_journal_v1(),
                );
                self.pin_io.observe_receiving_v1(&request, dispatch.attempt(), cutoff, &mut stage)
            } else {
                self.pin_io.observe(&request, dispatch.attempt())
            };
            let result = original.worker_result_v1(result, selected)?;
            let completion = match receiving.as_deref_mut() {
                Some(receiving) => self.coordinator.complete_workspace_pin_observation_receiving_v1(
                    dispatch.attempt(), &result, receiving,
                ),
                None => self.coordinator.complete_workspace_pin_observation(dispatch.attempt(), &result),
            };
            match original.helper_result_v1(completion, selected)?
            {
                crate::workspace_pin::WorkspacePinRecoveryDispositionV1::CompletePublication
                | crate::workspace_pin::WorkspacePinRecoveryDispositionV1::CompleteRetirement => {}
                _ => pending += 1,
            }
        }
        let current_host_scope = original.worker_result_v1(self.pin_io.host_scope(), selected)?;
        for dispatch in self
            .coordinator
            .workspace_pin_repair_observation_dispatches(&self.pin_contract, current_host_scope)
            .map_err(|_| StorageRuntimeError::Recovery)?
        {
            let request = match receiving.as_deref_mut() {
                Some(receiving) => dispatch.request_bytes_receiving_v1(receiving),
                None => dispatch.request_bytes(),
            };
            let request = original.helper_result_v1(request, selected)?;
            let result = if let Some(receiving) = receiving.as_deref_mut() {
                reserve_pin_result_v1(receiving)?;
                let cutoff = worker_cutoff_v1()?;
                let mut stage = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::state(
                    receiving, self.coordinator.recovery_encoding_journal_v1(),
                );
                self.pin_io.observe_repair_receiving_v1(&request, dispatch.attempt().attempt_id(),
                    dispatch.probe().digest(), cutoff, &mut stage)
            } else {
                self.pin_io.observe_repair(&request, dispatch.attempt().attempt_id(), dispatch.probe().digest())
            };
            let result = original.worker_result_v1(result, selected)?;
            let completion = match receiving.as_deref_mut() {
                Some(receiving) => self.coordinator.complete_workspace_pin_repair_observation_receiving_v1(
                    dispatch, result, receiving,
                ),
                None => self.coordinator.complete_workspace_pin_repair_observation(dispatch, result),
            };
            match original.helper_result_v1(completion, selected)?
            {
                crate::workspace_pin::WorkspacePinRecoveryDispositionV1::CompletePublication => {}
                crate::workspace_pin::WorkspacePinRecoveryDispositionV1::AwaitFreshRepair => {
                    pending += 1;
                }
                _ => return Err(StorageRuntimeError::Recovery),
            }
        }
        let (workspace_plan, physical_plan) =
            self.coordinator.workspace_catalog_activation_plan()?;
        self.workspaces
            .as_mut()
            .ok_or(StorageRuntimeError::Recovery)?
            .revalidate_plan(workspace_plan)?;
        if let Some(readiness) = pending_startup_readiness(pending, physical_plan.is_some()) {
            return Ok(readiness);
        }

        let now = boottime_now_nanoseconds()?;
        let activation_deadline = now
            .checked_add(STARTUP_CATALOG_OBSERVATION_NANOSECONDS)
            .ok_or(StorageRuntimeError::Recovery)?;
        let worker_cutoff = now
            .checked_add(STARTUP_CATALOG_WORKER_NANOSECONDS)
            .ok_or(StorageRuntimeError::Recovery)?;
        let validated = self
            .workspaces
            .take()
            .ok_or(StorageRuntimeError::Recovery)?;
        if let Some(receiving) = receiving.as_deref_mut() {
            original.catalog.park_validated_v1(validated);
            original.catalog.observe_state_receiving_v1(
                self.coordinator, self.pin_io, self.configuration_binding, self.broker_instance_id,
                activation_deadline, worker_cutoff, self.operator_startup, receiving,
            )?;
            *self.workspaces = original.catalog.take_positive_validated_v1();
            if self.workspaces.is_none() {
                return Err(StorageRuntimeError::Receiving);
            }
            return Ok(StorageRuntimeReadiness::Ready);
        }
        match inventory_catalog::ordinary_from_validated_v1(
            self.coordinator, self.pin_io, self.configuration_binding, self.broker_instance_id,
            self.operator_startup, validated, activation_deadline, worker_cutoff,
        ) {
            Ok((validated, _)) => {
                *self.workspaces = Some(validated);
                Ok(StorageRuntimeReadiness::Ready)
            }
            Err((Some(validated), error)) => {
                *self.workspaces = Some(validated);
                Err(error)
            }
            Err((None, _)) => {
                *self.readiness = StorageRuntimeReadiness::ReopenRequired;
                Err(StorageRuntimeError::ReopenRequired)
            }
        }
    }
}

pub(super) fn reserve_pin_result_v1(receiving: &mut StateEncodingLoanV1<'_, '_>) -> Result<(), StorageRuntimeError> {
    let demand = crate::pin_worker::pin_returned_model_demand_v1().ok_or(StorageRuntimeError::Receiving)?;
    let bytes = usize::try_from(demand.get(aos_sandbox_core::ResourceDimension::MemoryBytes))
        .map_err(|_| StorageRuntimeError::Receiving)?;
    receiving.reserve_encoded_capacity_v1(bytes, 0).map_err(|_| StorageRuntimeError::Receiving)
}

fn worker_cutoff_v1() -> Result<u64, StorageRuntimeError> {
    boottime_now_nanoseconds()?.checked_add(STARTUP_CATALOG_WORKER_NANOSECONDS)
        .ok_or(StorageRuntimeError::Recovery)
}

impl StorageBrokerRuntime {
    pub(super) fn reconcile_startup(&mut self) -> Result<StorageRuntimeReadiness, StorageRuntimeError> {
        let mut ordinary = StartupReconciliationOriginalV1::new();
        self.reconciliation_parts_v1().run(&mut ordinary, None, None)
    }

    fn reconciliation_parts_v1(&mut self) -> ReconciliationPartsV1<'_> {
        ReconciliationPartsV1 {
            coordinator: &mut self.coordinator,
            helper: &mut self.helper,
            pin_io: self.pin_io.as_mut(),
            pin_contract: &self.pin_contract,
            native_issuance: &mut self.native_issuance,
            workspaces: &mut self.workspaces,
            worker_dispatch: &self.worker_dispatch,
            configuration_binding: self.configuration_binding,
            broker_instance_id: self.broker_instance_id,
            operator_startup: self.operator_startup.as_ref(),
            readiness: &mut self.readiness,
            resolver_policies: &mut self.resolver_policies,
            prepare_readiness: &mut self.prepare_readiness,
            policy_directory_original: &mut self.resolver_policy_directory_original,
            policy_read_original: &mut self.resolver_policy_read_original,
        }
    }

    /// Enters only the first completed-writer startup interval; later operation
    /// reconciliation requires its own lifecycle Domain lender.
    pub(super) fn reconcile_initial_receiving_v1(&mut self)
        -> Result<StorageRuntimeReadiness, StorageRuntimeError>
    {
        self.reconcile_initial_state_inner_v1(InitialStatePurposeV1::Direct)
    }

    pub(super) fn resume_initial_operator_receiving_v1(&mut self) -> Result<(), StorageRuntimeError> {
        let result = self.reconcile_initial_state_inner_v1(InitialStatePurposeV1::DeferredOperator);
        match result {
            Ok(readiness) => {
                self.readiness = readiness;
                Ok(())
            }
            Err(cause) => {
                self.latch_reopen_required();
                Err(cause)
            }
        }
    }

    fn reconcile_initial_state_inner_v1(&mut self, purpose: InitialStatePurposeV1)
        -> Result<StorageRuntimeReadiness, StorageRuntimeError>
    {
        match purpose {
            InitialStatePurposeV1::Direct if self.operator_startup.is_some() =>
                return Err(StorageRuntimeError::Receiving),
            InitialStatePurposeV1::DeferredOperator if !self.operator_startup.as_ref()
                .is_some_and(|startup| !startup.has_debt()) =>
                return Err(StorageRuntimeError::Receiving),
            _ => {}
        }
        let original = &mut self.startup_reconciliation;
        if original.entered {
            return Err(StorageRuntimeError::Receiving);
        }
        original.entered = true;
        let startup = self.original_worker_startup.as_mut().ok_or(StorageRuntimeError::Receiving)?;
        let mut raw = startup.borrow_storage_prepare_receiving_v1().map_err(|_| StorageRuntimeError::Receiving)?;
        let mut receiving = self.coordinator.borrow_state_recovery_encoding_v1(&mut raw)
            .map_err(|_| StorageRuntimeError::Receiving)?;
        let mut parts = ReconciliationPartsV1 {
            coordinator: &mut self.coordinator,
            helper: &mut self.helper,
            pin_io: self.pin_io.as_mut(),
            pin_contract: &self.pin_contract,
            native_issuance: &mut self.native_issuance,
            workspaces: &mut self.workspaces,
            worker_dispatch: &self.worker_dispatch,
            configuration_binding: self.configuration_binding,
            broker_instance_id: self.broker_instance_id,
            operator_startup: self.operator_startup.as_ref(),
            readiness: &mut self.readiness,
            resolver_policies: &mut self.resolver_policies,
            prepare_readiness: &mut self.prepare_readiness,
            policy_directory_original: &mut self.resolver_policy_directory_original,
            policy_read_original: &mut self.resolver_policy_read_original,
        };
        let prelude = match purpose {
            InitialStatePurposeV1::Direct => None,
            InitialStatePurposeV1::DeferredOperator => self.operator_startup.as_ref(),
        };
        let result = parts.run_paid_v1(original, &mut receiving, prelude);
        drop(receiving);
        let readiness = result?;

        // Construction still owes its final service and held-key bookends.
        // Keep every actual positive owner resident until that real caller
        // reaches the explicit disposition below.
        Ok(readiness)
    }

    pub(crate) fn reconcile_lifecycle_domain_receiving_v1(
        &mut self,
        lifecycle: &mut aos_sandbox::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
    ) -> Result<StorageRuntimeReadiness, StorageRuntimeError> {
        let original = &mut self.startup_reconciliation;
        if original.entered || self.operator_startup.is_some() {
            return Err(StorageRuntimeError::Receiving);
        }
        // The parent Domain guard remains continuously borrowed across this
        // same-State subloan, real physical dispatch and independent posts.
        let mut receiving = lifecycle.borrow_state_encoding_v1(
            session, socket, self.coordinator.recovery_encoding_journal_v1(),
        ).map_err(|_| StorageRuntimeError::Receiving)?;
        original.entered = true;
        let mut parts = ReconciliationPartsV1 {
            coordinator: &mut self.coordinator,
            helper: &mut self.helper,
            pin_io: self.pin_io.as_mut(),
            pin_contract: &self.pin_contract,
            native_issuance: &mut self.native_issuance,
            workspaces: &mut self.workspaces,
            worker_dispatch: &self.worker_dispatch,
            configuration_binding: self.configuration_binding,
            broker_instance_id: self.broker_instance_id,
            operator_startup: None,
            readiness: &mut self.readiness,
            resolver_policies: &mut self.resolver_policies,
            prepare_readiness: &mut self.prepare_readiness,
            policy_directory_original: &mut self.resolver_policy_directory_original,
            policy_read_original: &mut self.resolver_policy_read_original,
        };
        let result = parts.run_paid_v1(original, &mut receiving, None);
        drop(receiving);
        let readiness = result?;
        self.readiness = readiness;
        Ok(readiness)
    }

    pub(crate) fn prepare_lifecycle_apply_models_v1(
        &mut self,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageRuntimeError> {
        let original = &mut self.startup_reconciliation;
        if original.entered || self.operator_startup.is_some() {
            return Err(StorageRuntimeError::Receiving);
        }
        original.entered = true;
        let mut parts = ReconciliationPartsV1 {
            coordinator: &mut self.coordinator,
            helper: &mut self.helper,
            pin_io: self.pin_io.as_mut(),
            pin_contract: &self.pin_contract,
            native_issuance: &mut self.native_issuance,
            workspaces: &mut self.workspaces,
            worker_dispatch: &self.worker_dispatch,
            configuration_binding: self.configuration_binding,
            broker_instance_id: self.broker_instance_id,
            operator_startup: None,
            readiness: &mut self.readiness,
            resolver_policies: &mut self.resolver_policies,
            prepare_readiness: &mut self.prepare_readiness,
            policy_directory_original: &mut self.resolver_policy_directory_original,
            policy_read_original: &mut self.resolver_policy_read_original,
        };

        parts.prepare_paid_models_v1(original, receiving);
        if !matches!(original.model, Some(Ok(()))) || !matches!(original.capacity, Some(Ok(()))) {
            return Err(StorageRuntimeError::Receiving);
        }
        Ok(())
    }

    pub(crate) fn reserve_lifecycle_inventory_models_v1(
        &mut self,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageRuntimeError> {
        let demand = self.inventory_retention_demand_v1();
        let demand = match demand {
            Ok(demand) => demand,
            Err(cause) => {
                self.startup_reconciliation.arithmetic = Some(cause);
                return Err(StorageRuntimeError::Receiving);
            }
        };
        self.startup_reconciliation.capacity = Some(receiving.reserve_inventory_readback_v1(
            self.coordinator.recovery_encoding_journal_v1(), demand,
        ));
        if matches!(self.startup_reconciliation.capacity, Some(Ok(()))) {
            Ok(())
        } else {
            Err(StorageRuntimeError::Receiving)
        }
    }

    pub(crate) fn reserve_lifecycle_preparation_models_v1(
        &mut self,
        request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageRuntimeError> {
        let demand = self.coordinator.receiving_inventory_geometry_v1()
            .and_then(|shape| shape.retained_model_demand_v1())
            .and_then(|state| ProtectedStorageResolverPolicyDirectoryV1::receiving_demand_v1()
                .and_then(|policy| state.checked_add(policy)))
            .and_then(|current| crate::catalog_preparation::receiving_preparation_demand_v1(
                request_body.len(), artifacts,
            ).and_then(|preparation| current.checked_add(preparation)));
        let demand = match demand {
            Ok(demand) => demand,
            Err(cause) => {
                self.startup_reconciliation.arithmetic = Some(cause);
                return Err(StorageRuntimeError::Receiving);
            }
        };
        self.startup_reconciliation.capacity = Some(receiving.reserve_preparation_models_v1(
            self.coordinator.recovery_encoding_journal_v1(), demand,
        ));
        if matches!(self.startup_reconciliation.capacity, Some(Ok(()))) {
            Ok(())
        } else {
            Err(StorageRuntimeError::Receiving)
        }
    }

    pub(super) fn reconcile_entered_state_v1(
        &mut self,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<StorageRuntimeReadiness, StorageRuntimeError> {
        let original = &mut self.startup_reconciliation;
        if !original.entered || !matches!(original.model, Some(Ok(())))
            || !matches!(original.capacity, Some(Ok(()))) || original.post.is_some()
        {
            return Err(StorageRuntimeError::Receiving);
        }
        let mut parts = ReconciliationPartsV1 {
            coordinator: &mut self.coordinator,
            helper: &mut self.helper,
            pin_io: self.pin_io.as_mut(),
            pin_contract: &self.pin_contract,
            native_issuance: &mut self.native_issuance,
            workspaces: &mut self.workspaces,
            worker_dispatch: &self.worker_dispatch,
            configuration_binding: self.configuration_binding,
            broker_instance_id: self.broker_instance_id,
            operator_startup: None,
            readiness: &mut self.readiness,
            resolver_policies: &mut self.resolver_policies,
            prepare_readiness: &mut self.prepare_readiness,
            policy_directory_original: &mut self.resolver_policy_directory_original,
            policy_read_original: &mut self.resolver_policy_read_original,
        };

        original.result = Some(parts.run(original, Some(receiving), None));
        match original.result.as_ref() {
            Some(Ok(readiness)) => Ok(*readiness),
            _ => Err(StorageRuntimeError::Receiving),
        }
    }

    pub(crate) fn finish_lifecycle_apply_posts_v1<T>(
        &mut self,
        result: Result<T, crate::DormantStorageBrokerCallErrorV1>,
        receiving: &mut StateEncodingLoanV1<'_, '_>,
    ) -> Result<T, crate::DormantStorageBrokerCallErrorV1> {
        // This is still the same entered State loan. The returned domain
        // failure is parked before either independent owed observation.
        let value = match result {
            Ok(value) => Some(value),
            Err(cause) => {
                self.startup_reconciliation.application_error = Some(cause);
                None
            }
        };
        if value.is_some() && self.startup_reconciliation.result.is_none() {
            self.startup_reconciliation.result = Some(Ok(self.readiness));
        }
        self.startup_reconciliation.post = Some(self.coordinator.finish_recovery_posts_v1(receiving));
        match value {
            Some(value) if matches!(self.startup_reconciliation.post, Some(Ok(()))) => Ok(value),
            _ => Err(StorageRuntimeError::Receiving.into()),
        }
    }

    pub(crate) fn prepare_lifecycle_reconciliation_disposal_v1<'runtime, 'phase, 'cut, 'original>(
        &'runtime mut self,
        native: aos_sandbox::StorageLifecyclePositiveDisposalV1<'phase, 'cut, 'original>,
    ) -> Result<super::StorageRuntimeLifecycleDisposalV1<'runtime, 'phase, 'cut, 'original>, StorageRuntimeError> {
        native.require_state_reconciliation_disposal_v1(self.coordinator.recovery_encoding_journal_v1())
            .map_err(|_| StorageRuntimeError::Receiving)?;
        if !self.startup_reconciliation.entered
            || !matches!(self.startup_reconciliation.result, Some(Ok(_)))
            || !matches!(self.startup_reconciliation.post, Some(Ok(())))
            || self.startup_reconciliation.application_error.is_some()
            || matches!(self.startup_reconciliation.pin_ensure_result, Some(Err(_)))
            || matches!(self.startup_reconciliation.pin_remove_result, Some(Err(_)))
        {
            return Err(StorageRuntimeError::Receiving);
        }
        if self.guest_root_publication.as_ref().is_some_and(|owner| !owner.completed_v2()) {
            return Err(StorageRuntimeError::Receiving);
        }
        // These existing tokens check their whole actual owners; none disposes
        // on Drop. The returned exclusive Runtime borrow prevents mutation of
        // any checked owner until the final infallible completion.
        if self.startup_reconciliation.catalog.finished_inventory_v1()
            || self.startup_reconciliation.preparation_complete
            || self.guest_root_publication.as_ref().is_some_and(|owner| owner.completed_v2())
        {
            drop(self.startup_reconciliation.transactions.prepare_positive_or_unused_disposal_v1()?);
        } else {
            drop(self.startup_reconciliation.transactions.prepare_positive_disposal_v1()?);
        }
        drop(self.helper.prepare_recovery_disposition_v1().map_err(|_| StorageRuntimeError::Receiving)?);
        drop(self.coordinator.prepare_recovery_disposition_v1()?);
        Ok(super::StorageRuntimeLifecycleDisposalV1 { runtime: self, native })
    }

    pub(super) fn complete_initial_reconciliation_disposal_v1(&mut self)
        -> Result<(), StorageRuntimeError>
    {
        let original = &mut self.startup_reconciliation;
        if !original.entered || !matches!(original.result, Some(Ok(_)))
            || !matches!(original.post, Some(Ok(())))
        {
            return Err(StorageRuntimeError::Receiving);
        }
        // Every fallible prerequisite is checked with all actual native and
        // upper owners resident. The following tokens perform only disposal.
        let transactions = original.transactions.prepare_positive_disposal_v1()?;
        let helper = self.helper.prepare_recovery_disposition_v1().map_err(|_| StorageRuntimeError::Receiving)?;
        let coordinator = self.coordinator.prepare_recovery_disposition_v1()?;
        transactions.complete_after_disposal_v1();
        helper.complete_after_disposal_v1();
        coordinator.complete_after_disposal_v1();
        drop(self.operator_startup.take());
        self.startup_reconciliation = StartupReconciliationOriginalV1::new();
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_entry_requires_actual_operator_startup_custody() {
        let transactions = tempfile::tempdir().unwrap();
        let workspaces = tempfile::tempdir().unwrap();
        let mut runtime = crate::broker::native_runtime_fixture_for_test(&transactions, &workspaces);
        let before: Vec<_> = runtime.coordinator.recovery_encoding_journal_v1().all_records()
            .map(|(namespace, key, value)| (namespace, key.to_vec(), value.to_vec())).collect();

        assert!(matches!(runtime.resume_initial_operator_receiving_v1(), Err(StorageRuntimeError::Receiving)));

        assert!(!runtime.startup_reconciliation.entered);
        let after: Vec<_> = runtime.coordinator.recovery_encoding_journal_v1().all_records()
            .map(|(namespace, key, value)| (namespace, key.to_vec(), value.to_vec())).collect();
        assert_eq!(before, after);
        assert_eq!(runtime.readiness, StorageRuntimeReadiness::ReopenRequired);
    }

    #[test]
    fn real_retirement_error_precedes_later_independent_post_by_reference() {
        let transactions = tempfile::tempdir().unwrap();
        let workspaces = tempfile::tempdir().unwrap();
        let runtime = crate::broker::native_runtime_fixture_for_test(&transactions, &workspaces);
        let mut original = StartupReconciliationOriginalV1::new();
        original.operator_retirement_error = Some(crate::helper::ZfsHelperError::Backend(
            ZfsWorkerError::Protocol("actual earlier retirement failure"),
        ));
        original.result = Some(Err(StorageRuntimeError::Recovery));
        original.post = Some(Err(aos_sandbox::StorageReceivingClosedV1));

        let actual = original.operator_retirement_error.as_ref().unwrap();
        let reported = original.failure(&runtime.coordinator, &runtime.helper).unwrap()
            .downcast_ref::<crate::helper::ZfsHelperError>().unwrap();

        assert!(std::ptr::eq(actual, reported));
    }

    #[test]
    fn physical_primary_precedes_later_owed_post_by_reference() {
        let transactions = tempfile::tempdir().unwrap();
        let workspaces = tempfile::tempdir().unwrap();
        let runtime = crate::broker::native_runtime_fixture_for_test(&transactions, &workspaces);
        let mut original = StartupReconciliationOriginalV1::new();
        original.worker_error = Some(ZfsWorkerError::Protocol("actual earlier worker failure"));
        original.result = Some(Err(StorageRuntimeError::Recovery));
        original.post = Some(Err(aos_sandbox::StorageReceivingClosedV1));

        let actual = original.worker_error.as_ref().unwrap();
        let reported = original.failure(&runtime.coordinator, &runtime.helper)
            .unwrap().downcast_ref::<ZfsWorkerError>().unwrap();

        assert!(std::ptr::eq(actual, reported));
    }

    #[test]
    fn initial_receiving_without_original_cannot_enter_ordinary_reconciliation() {
        let transactions = tempfile::tempdir().unwrap();
        let workspaces = tempfile::tempdir().unwrap();
        let mut runtime = crate::broker::native_runtime_fixture_for_test(&transactions, &workspaces);
        let before: Vec<_> = runtime.coordinator.recovery_encoding_journal_v1().all_records()
            .map(|(namespace, key, value)| (namespace, key.to_vec(), value.to_vec())).collect();

        assert!(matches!(runtime.reconcile_initial_receiving_v1(), Err(StorageRuntimeError::Receiving)));

        let after: Vec<_> = runtime.coordinator.recovery_encoding_journal_v1().all_records()
            .map(|(namespace, key, value)| (namespace, key.to_vec(), value.to_vec())).collect();
        assert_eq!(before, after);
        assert!(!runtime.startup_reconciliation.transactions.entered_for_test_v1());
    }

    #[test]
    fn startup_and_recurring_helper_errors_keep_distinct_original_destinations() {
        let mut original = StartupReconciliationOriginalV1::new();

        assert!(original.helper_result_v1::<()>(
            Err(crate::helper::ZfsHelperError::PreconditionMismatch), true,
        ).is_err());
        assert!(original.operation_result_v1::<()>(
            Err(crate::helper::ZfsHelperError::PostconditionMismatch), true,
        ).is_err());

        assert!(matches!(original.helper_error,
            Some(crate::helper::ZfsHelperError::PreconditionMismatch)));
        assert!(matches!(original.operation_error,
            Some(crate::helper::ZfsHelperError::PostconditionMismatch)));
    }
}

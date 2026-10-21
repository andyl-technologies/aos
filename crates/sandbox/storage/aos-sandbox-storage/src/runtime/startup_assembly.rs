//! Actual partial Runtime owners retained across common startup failures.
//!
//! This is passive custody, not a writer or funding factory. The selected
//! Construction parks it before projecting any error. The legacy wrapper
//! keeps a local instance with its existing reverse native drop ordering.

use super::*;

pub(super) struct StorageRuntimeAssemblyV1 {
    pub(super) operator_owner: Option<crate::operator_recovery::StorageOperatorRecoveryOwnerV1>,
    pub(super) native_issuance: Option<StorageNativeIssuanceLedgerV1>,
    pub(super) trust_startup: crate::live_export_request_trust::StorageLiveExportRequestTrustOpenV1,
    pub(super) issuance_startup: crate::native_issuance::StorageNativeIssuanceStartupV1,
    pub(super) workspaces: Option<ValidatedPendingStorageWorkspaceCatalogV1>,
    pub(super) workspace_startup: crate::workspace_catalog::StorageWorkspaceStartupV1,
    pub(super) workspace_plan: Option<Result<(
        crate::workspace_catalog::StorageWorkspaceCatalogPlanV1,
        Option<crate::broker::AuthenticatedWorkspaceCatalogPhysicalPlanV1>,
    ), StorageBrokerError>>,
    pub(super) selected_workspace_plan: Option<crate::workspace_catalog::StorageWorkspaceCatalogPlanV1>,
    pub(super) physical_workspace_plan: Option<crate::broker::AuthenticatedWorkspaceCatalogPhysicalPlanV1>,
    pub(super) resolver_configuration: Option<Result<(
        Option<ProtectedStorageResolverPolicyDirectoryV1>, StoragePrepareReadiness,
    ), StorageRuntimeError>>,
    pub(super) resolver_policies: Option<ProtectedStorageResolverPolicyDirectoryV1>,
    pub(super) resolver_policy_directory_original: crate::resolver::protected_catalog::ResolverPolicyDirectoryOriginalV1,
    pub(super) resolver_policy_read_original: crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1,
    pub(super) startup_retirement: Option<Result<Vec<crate::broker::PreparedStorageRetirementV1>, crate::helper::ZfsHelperError>>,
    pub(super) startup_mutation_entry: Option<Result<(), StorageBrokerError>>,
    pub(super) startup_authority: Option<Result<(), StorageRuntimeError>>,
    pub(super) startup_mutation_posts: Option<Result<(), StorageBrokerError>>,
    pub(super) coordinator: Option<StorageAdmissionCoordinator>,
    pub(super) guest_root_publisher: Option<SystemdGuestRootPublisherClientV1>,
    pub(super) pin_io: Option<SystemdWorkspacePinRuntimeIo>,
    pub(super) initial_pin_borrow: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    pub(super) initial_pin_scan: Option<Result<(), ZfsWorkerError>>,
    pub(super) initial_pin_disposal: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    pub(super) pin_observer: Option<SystemdWorkspacePinObserver>,
    pub(super) pin_executor: Option<SystemdWorkspacePinExecutor>,
    pub(super) transactions: Option<StorageTransactionStore>,
    pub(super) state_startup: crate::state::StorageStateStartupV1,
    pub(super) broker_configuration_open: aos_sandbox_broker::ProtectedStorageBrokerConfigurationOriginalV1,
    pub(super) broker_configuration: Option<aos_sandbox_broker::ProtectedBrokerAuthorityConfiguration>,
    pub(super) configuration_conversion: crate::authorization::StorageProtectedConfigurationConversionV1,
    pub(super) configuration_before: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    pub(super) configuration_capture: Option<Result<(), crate::StorageAuthorityConfigError>>,
    pub(super) configuration_conversion_result: Option<Result<(), crate::StorageAuthorityConfigError>>,
    pub(super) configuration_post: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    pub(super) bootstrap: Option<ProtectedStorageBootstrap>,
    pub(super) bootstrap_open: super::bootstrap_open::ProtectedStorageBootstrapOpenV1,
    pub(super) bootstrap_before: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    pub(super) bootstrap_capture: Option<Result<(), StorageRuntimeError>>,
    pub(super) bootstrap_post: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    pub(super) authority: Option<crate::authorization::StorageAuthorityV1>,
    pub(super) state_key: Option<crate::state::StorageStateKey>,
    pub(super) pin_custody: Option<WorkspacePinHostCustody>,
    pub(super) pin_capture: crate::pin_observer::WorkspacePinHostCaptureV1,
    pub(super) pin_capture_result: Option<Result<WorkspacePinHostCustody, crate::pin_observer::WorkspacePinObserverError>>,
}

impl StorageRuntimeAssemblyV1 {
    pub(super) fn new() -> Self {
        Self {
            operator_owner: None,
            native_issuance: None,
            trust_startup: crate::live_export_request_trust::StorageLiveExportRequestTrustOpenV1::new(),
            issuance_startup: crate::native_issuance::StorageNativeIssuanceStartupV1::new(),
            workspaces: None,
            workspace_startup: crate::workspace_catalog::StorageWorkspaceStartupV1::new(),
            workspace_plan: None,
            selected_workspace_plan: None,
            physical_workspace_plan: None,
            resolver_configuration: None,
            resolver_policies: None,
            resolver_policy_directory_original: crate::resolver::protected_catalog::ResolverPolicyDirectoryOriginalV1::new(),
            resolver_policy_read_original: crate::resolver::protected_catalog::ResolverPolicyReadOriginalV1::new(),
            startup_retirement: None,
            startup_mutation_entry: None,
            startup_authority: None,
            startup_mutation_posts: None,
            coordinator: None,
            guest_root_publisher: None,
            pin_io: None,
            initial_pin_borrow: None,
            initial_pin_scan: None,
            initial_pin_disposal: None,
            pin_observer: None,
            pin_executor: None,
            transactions: None,
            state_startup: crate::state::StorageStateStartupV1::new(),
            broker_configuration_open: aos_sandbox_broker::ProtectedStorageBrokerConfigurationOriginalV1::new(),
            broker_configuration: None,
            configuration_conversion: crate::authorization::StorageProtectedConfigurationConversionV1::new(),
            configuration_before: None,
            configuration_capture: None,
            configuration_conversion_result: None,
            configuration_post: None,
            bootstrap: None,
            bootstrap_open: super::bootstrap_open::ProtectedStorageBootstrapOpenV1::new(),
            bootstrap_before: None,
            bootstrap_capture: None,
            bootstrap_post: None,
            authority: None,
            state_key: None,
            pin_custody: None,
            pin_capture: crate::pin_observer::WorkspacePinHostCaptureV1::default(),
            pin_capture_result: None,
        }
    }

    pub(super) fn initial_pin_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.pin_capture.failure()
            .or_else(|| self.pin_capture_result.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.initial_pin_borrow.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.initial_pin_scan.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| match cause.physical_native_refusal_v1() {
                    Some(marker) => marker as &dyn std::error::Error,
                    None => cause as &dyn std::error::Error,
                }))
            .or_else(|| self.initial_pin_disposal.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error))
    }

    // The shared engine preflights these exact slots before its final positive
    // Snapshot/executor handoff. No fallible IO or authority check follows.
    pub(super) fn take_coordinator(&mut self) -> StorageAdmissionCoordinator {
        match self.coordinator.take() {
            Some(coordinator) => coordinator,
            None => std::process::abort(),
        }
    }

    pub(super) fn take_workspaces(&mut self) -> ValidatedPendingStorageWorkspaceCatalogV1 {
        match self.workspaces.take() {
            Some(workspaces) => workspaces,
            None => std::process::abort(),
        }
    }

    pub(super) fn take_pin_io(&mut self) -> SystemdWorkspacePinRuntimeIo {
        match self.pin_io.take() {
            Some(pin_io) => pin_io,
            None => std::process::abort(),
        }
    }

}

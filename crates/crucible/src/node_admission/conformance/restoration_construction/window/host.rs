//! Invokes the actual fourth Host2 validator before complete scope issuance.
//!
//! This nonconstructible loan contains the same verified archive and genuine
//! target. It carries no proof placeholder, final context or readiness flag.
//! Core routes it only to the exact existing Host node; that node repeats the
//! original Host2 runtime/body/owner/journal predicates on its actual source.

use super::*;
use crate::node_contract::{
    OriginalLineageJournal, OriginalLineageOwnerMapping, OriginalLineageRuntimeRecord,
};

/// Borrows exact fields for the original runtime-owned fourth Host2 validator.
pub struct OriginalRestorationHostContinuationInspection<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    plan: &'a InstalledConformancePlan,
    activation: &'a ActivationRecord,
    owners: &'a [OriginalLineageOwnerMapping],
    journals: &'a [OriginalLineageJournal],
    installed_scope: Option<&'a crate::node_contract::OriginalLineageNativeScope>,
}

impl OriginalRestorationHostContinuationInspection<'_> {
    pub(crate) fn archive_data(&self) -> &CompleteOriginalRestorationSource {
        &self.window.archive
    }

    pub(crate) fn source_record_data(&self) -> &ContentRef {
        self.window.archive.runtime_object()
    }

    pub(crate) fn record_data(&self) -> Result<&OriginalLineageRuntimeRecord, RuntimeError> {
        self.window.archive.original_runtime_record_data()
    }

    pub(crate) fn target_data(&self) -> &ActivationRecord {
        self.activation
    }

    pub(crate) fn owner_mappings_data(&self) -> &[OriginalLineageOwnerMapping] {
        self.owners
    }

    pub(crate) fn journals_data(&self) -> &[OriginalLineageJournal] {
        self.journals
    }

    pub(crate) fn node_data(&self) -> Result<&Id, RuntimeError> {
        Ok(&self
            .window
            .archive
            .original_host_record_data()?
            .source
            .descriptor
            .id)
    }

    pub(crate) fn authenticate_runtime_data(
        &self,
        runtime: &ConformanceRuntime,
    ) -> Result<(), RuntimeError> {
        runtime.authenticate_original_restoration_target_data(
            &self.window.archive,
            self.plan,
            self.activation,
        )?;
        self.authenticate_current()
    }

    pub(crate) fn authenticate_current(&self) -> Result<(), RuntimeError> {
        if let Some(scope) = self.installed_scope {
            return self
                .window
                .authenticate_original_complete_member_data(self.plan, scope);
        }
        self.window.origin()?;
        if self.window.stage.get() != WindowStage::TransactionAdmitted {
            return Err(RuntimeError::OutstandingObligations);
        }
        for selected in 0..3 {
            let target = self.window.targets[selected]
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            self.window.authenticate_original_completed_member_data(
                target,
                &self.window.sources[selected],
                self.plan,
                self.activation,
            )?;
        }
        self.window
            .authenticate_original_runtime_member_current_data(&self.activation.world_binding_hash)
    }
}

impl CompleteOriginalRestorationWindow {
    pub(super) fn inspect_original_host_continuation_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &ConformanceRuntime,
        activation: &ActivationRecord,
        owners: &[OriginalLineageOwnerMapping],
        journals: &[OriginalLineageJournal],
    ) -> Result<(), RuntimeError> {
        let inspection = OriginalRestorationHostContinuationInspection {
            window: self,
            plan,
            activation,
            owners,
            journals,
            installed_scope: None,
        };
        inspection.authenticate_runtime_data(runtime)?;
        runtime.inspect_original_host_restoration_continuation(inspection)
    }
}

impl<'a> OriginalRestorationHostContinuationInspection<'a> {
    pub(super) fn for_original_installed_window(
        window: &'a CompleteOriginalRestorationWindow,
        plan: &'a InstalledConformancePlan,
        scope: &'a crate::node_contract::OriginalLineageNativeScope,
    ) -> Self {
        Self {
            window,
            plan,
            activation: &scope.target,
            owners: &scope.owners,
            journals: &scope.journals,
            installed_scope: Some(scope),
        }
    }
}

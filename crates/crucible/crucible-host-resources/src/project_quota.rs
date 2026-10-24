//! Binds persistent quota audits to their original Crucible supervision.
//!
//! The shared quota crate owns kernel authentication and namespace traversal.
//! This adapter owns operation admission and the actual typed refusal. Its
//! audit borrows the same guard throughout; no callback creates another clock.

use std::cell::Cell;
use std::path::Path;

use aos_linux_project_quota::{
    AuditedProjectQuotaBinding, LinuxProjectQuotaError, QuotaAudit, QuotaAuditRefusal,
};
use thiserror::Error;

use crate::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor, HostSupervisionError,
};

/// Retains the actual kernel or supervision cause of a persistent quota refusal.
#[derive(Debug, Error)]
pub enum SupervisedProjectQuotaError {
    /// Kernel quota authentication, namespace traversal or admission refused.
    #[error(transparent)]
    Quota(#[from] LinuxProjectQuotaError),
    /// The same original operation refused further quota effects.
    #[error("project-quota operation supervision failed: {0}")]
    Supervision(#[from] HostSupervisionError),
}

/// Pins an audited persistent quota under its existing supervision owner.
#[derive(Debug)]
pub struct SupervisedProjectQuotaBinding {
    binding: AuditedProjectQuotaBinding,
    supervisor: HostOperationSupervisor,
}

struct SupervisedAudit<'a> {
    operation: &'a HostOperationGuard,
    first: Cell<Option<HostSupervisionError>>,
}

type ProjectAdmission<'a> = &'a mut dyn FnMut((u64, u32)) -> Result<(), LinuxProjectQuotaError>;

impl SupervisedAudit<'_> {
    fn observe(&self, result: Result<(), HostSupervisionError>) -> Result<(), QuotaAuditRefusal> {
        result.map_err(|first| {
            if self.first.get().is_none() {
                self.first.set(Some(first));
            }
            QuotaAuditRefusal
        })
    }

    fn result<T>(
        &self,
        result: Result<T, LinuxProjectQuotaError>,
    ) -> Result<T, SupervisedProjectQuotaError> {
        match result {
            Err(LinuxProjectQuotaError::AuditRefused(refusal)) => match self.first.get() {
                Some(first) => Err(SupervisedProjectQuotaError::Supervision(first)),
                None => Err(LinuxProjectQuotaError::AuditRefused(refusal).into()),
            },
            result => result.map_err(Into::into),
        }
    }
}

impl QuotaAudit for SupervisedAudit<'_> {
    #[inline]
    fn check(&self) -> Result<(), QuotaAuditRefusal> {
        self.observe(self.operation.wait_slice().map(|_| ()))
    }

    #[inline]
    fn progress(&self, completed: u64) -> Result<(), QuotaAuditRefusal> {
        self.observe(self.operation.progress(completed))
    }
}

impl SupervisedProjectQuotaBinding {
    /// Audits an existing persistent quota using one newly admitted Preparation.
    ///
    /// The caller reserves the full audit peak before entry: 36 descriptors
    /// and 68 KiB of scan scratch, plus its existing stack and runtime overhead.
    /// Descendants must be directories or singly linked regular files in the
    /// same inherited project, with at most sixteen directory levels.
    ///
    /// # Errors
    /// Refuses original supervision, invalid limits, changed quota authority,
    /// unsafe namespace contents or failed kernel authentication.
    pub fn bind_existing_supervised(
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
        supervisor: HostOperationSupervisor,
    ) -> Result<Self, SupervisedProjectQuotaError> {
        let operation = supervisor.begin_work(HostOperationClass::Preparation, maximum_inodes)?;
        let binding = Self::bind(
            root,
            project_id,
            maximum_physical_bytes,
            maximum_inodes,
            supervisor,
            &operation,
            false,
            None,
        )?;
        operation.complete()?;
        Ok(binding)
    }

    /// Audits a persistent namespace under the caller's original Preparation.
    ///
    /// The supplied guard is neither completed nor restarted here. An uncertain
    /// audit retains the original directory and lease; the caller must retain
    /// their existing resource charge as well.
    ///
    /// # Errors
    /// Refuses the same original guard, invalid or changed quota authority,
    /// unsafe descendants or failed namespace authentication.
    pub fn bind_existing_under(
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
        supervisor: HostOperationSupervisor,
        operation: &HostOperationGuard,
    ) -> Result<Self, SupervisedProjectQuotaError> {
        Self::bind(
            root,
            project_id,
            maximum_physical_bytes,
            maximum_inodes,
            supervisor,
            operation,
            true,
            None,
        )
    }

    /// Charges an authenticated project before creating its namespace lease.
    ///
    /// The callback receives only verified filesystem/project identity. Failed
    /// admission precedes the first namespace effect. Uncertain later failure
    /// retains the same pins and lease, and the caller retains its receipts.
    ///
    /// # Errors
    /// Refuses original supervision, quota or namespace authentication, the
    /// caller's project admission, or completion of that same Preparation.
    pub fn bind_existing_admitted(
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
        supervisor: HostOperationSupervisor,
        admission: &mut dyn FnMut((u64, u32)) -> Result<(), LinuxProjectQuotaError>,
    ) -> Result<Self, SupervisedProjectQuotaError> {
        let operation = supervisor.begin_work(HostOperationClass::Preparation, maximum_inodes)?;
        let binding = Self::bind(
            root,
            project_id,
            maximum_physical_bytes,
            maximum_inodes,
            supervisor,
            &operation,
            true,
            Some(admission),
        )?;
        if let Err(first) = operation.complete() {
            std::mem::forget(binding);
            return Err(first.into());
        }
        Ok(binding)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Quota geometry, retained supervision and namespace disposition remain explicit."
    )]
    fn bind(
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
        supervisor: HostOperationSupervisor,
        operation: &HostOperationGuard,
        retain_uncertain_namespace: bool,
        admission: Option<ProjectAdmission<'_>>,
    ) -> Result<Self, SupervisedProjectQuotaError> {
        let audit = SupervisedAudit {
            operation,
            first: Cell::new(None),
        };
        let binding = audit.result(AuditedProjectQuotaBinding::bind_existing_audited(
            root,
            project_id,
            maximum_physical_bytes,
            maximum_inodes,
            &audit,
            retain_uncertain_namespace,
            admission,
        ))?;
        Ok(Self {
            binding,
            supervisor,
        })
    }

    /// Reauthenticates the original quota and namespace under one Writeback.
    ///
    /// # Errors
    /// Refuses original supervision, changed namespace or quota authority,
    /// changed limits or excessive current usage.
    pub fn verify(&self) -> Result<(), SupervisedProjectQuotaError> {
        let operation = self.supervisor.begin(HostOperationClass::Writeback)?;
        self.binding.verify()?;
        operation.complete()?;
        Ok(())
    }

    /// Creates a bounded directory chain under the same authenticated quota.
    ///
    /// # Errors
    /// Refuses original supervision, changed quota authority, escaped paths,
    /// unsafe namespace entries or failed filesystem operations.
    pub fn prepare_descendant_directory(
        &self,
        path: &Path,
    ) -> Result<(), SupervisedProjectQuotaError> {
        let operation = self.supervisor.begin(HostOperationClass::Preparation)?;
        let audit = SupervisedAudit {
            operation: &operation,
            first: Cell::new(None),
        };
        audit.result(
            self.binding
                .prepare_descendant_directory_under(path, &audit),
        )?;
        operation.complete()?;
        Ok(())
    }

    /// Returns the maximum simultaneously open descriptors during admission.
    #[must_use]
    pub const fn maximum_audit_file_descriptors() -> u64 {
        AuditedProjectQuotaBinding::maximum_audit_file_descriptors()
    }

    /// Returns the maximum bounded directory scan scratch bytes during admission.
    #[must_use]
    pub const fn maximum_audit_scratch_bytes() -> u64 {
        AuditedProjectQuotaBinding::maximum_audit_scratch_bytes()
    }
}

#[cfg(test)]
mod tests;

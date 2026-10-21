//! Pins existing quota namespaces and bounds their descriptor-relative audit.
//!
//! Kernel quota identity stays independent of any application's clock or resource
//! authority. Audited callers supply cooperative checks and retain their own
//! concrete refusal; these callbacks grant no quota, resource credit or cleanup.

use super::*;
use rustix::fs::open;

/// Checks caller-owned bounds during an existing quota namespace audit.
///
/// Implementations retain their concrete diagnostic when returning a refusal.
/// A check neither begins a new operation nor changes the kernel quota.
pub trait QuotaAudit {
    /// Checks whether the same admitted audit may perform its next bounded step.
    ///
    /// # Errors
    /// Returns a refusal when the caller's existing observation bounds expire.
    fn check(&self) -> Result<(), QuotaAuditRefusal>;

    /// Observes cumulative inventory progress under those same bounds.
    ///
    /// # Errors
    /// Returns a refusal when the caller cannot accept the observed work count.
    fn progress(&self, completed: u64) -> Result<(), QuotaAuditRefusal>;
}

/// Reports that the caller's original audit bounds refused further effects.
///
/// This status has no resource authority. The caller retains the concrete
/// supervision cause rather than allocating an erased diagnostic here.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("the caller's quota audit bounds refused further effects")]
pub struct QuotaAuditRefusal;

/// Pins an operator-installed quota without claiming a descendant audit.
#[derive(Debug)]
pub struct LinuxProjectQuotaBinding {
    directory: OwnedFd,
    path: PathBuf,
    device: u64,
    inode: u64,
    project_id: u32,
    limits: LinuxProjectQuotaLimits,
}

/// Pins an authenticated quota and its audited exclusive namespace lease.
///
/// The operator excludes uncooperative renames, mounts, hard links, project
/// changes and quota mutations. The lease excludes cooperating owners, not a
/// privileged administrator. This type can only be created by a complete audit.
#[derive(Debug)]
pub struct AuditedProjectQuotaBinding {
    binding: LinuxProjectQuotaBinding,
    namespace: descendants::NamespaceLease,
}

type ProjectAdmission<'a> = &'a mut dyn FnMut((u64, u32)) -> Result<(), LinuxProjectQuotaError>;

struct BindingScope<'operation, 'admission, A: QuotaAudit + ?Sized> {
    operation: &'operation A,
    retain_uncertain_namespace: bool,
    admission: Option<ProjectAdmission<'admission>>,
}

impl LinuxProjectQuotaBinding {
    /// Pins and verifies an already configured quota without auditing descendants.
    ///
    /// # Errors
    /// Refuses invalid limits or failed directory, filesystem, project or usage
    /// authentication. Audited namespace ownership uses [`AuditedProjectQuotaBinding`].
    pub fn bind_existing(
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<Self, LinuxProjectQuotaError> {
        if !project_id_is_supported(project_id) {
            return Err(LinuxProjectQuotaError::InvalidProjectId);
        }
        let limits = LinuxProjectQuotaLimits::new(maximum_physical_bytes, maximum_inodes)?;
        let directory = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| LinuxProjectQuotaError::Io {
            operation: "open-physical-quota-root",
            path: root.to_owned(),
            source: source.into(),
        })?;
        validate_ext4_filesystem(&directory, &directory, root)?;
        project_quota_info(&directory, root)?;
        verify_assigned_project(&directory, root, project_id)?;
        verify_project_quota(&directory, root, project_id, limits)?;
        verify_project_usage_within_limit(&directory, root, project_id, limits)?;
        let identity = fstat(&directory).map_err(|source| LinuxProjectQuotaError::Io {
            operation: "identify-physical-quota-root",
            path: root.to_owned(),
            source: source.into(),
        })?;
        Ok(Self {
            directory,
            path: root.to_owned(),
            device: identity.st_dev,
            inode: identity.st_ino,
            project_id,
            limits,
        })
    }

    /// Reauthenticates the pinned directory, project limits and current usage.
    ///
    /// # Errors
    /// Refuses changed identity, filesystem, project assignment, limits or usage.
    pub fn verify(&self) -> Result<(), LinuxProjectQuotaError> {
        let current = open(
            &self.path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| LinuxProjectQuotaError::Io {
            operation: "reopen-physical-quota-root",
            path: self.path.clone(),
            source: source.into(),
        })?;
        self.verify_identity(&current)?;
        self.verify_quota()
    }

    fn verify_identity(&self, current: &OwnedFd) -> Result<(), LinuxProjectQuotaError> {
        let identity = fstat(current).map_err(|source| LinuxProjectQuotaError::Io {
            operation: "reauthenticate-physical-quota-root",
            path: self.path.clone(),
            source: source.into(),
        })?;
        if identity.st_dev != self.device || identity.st_ino != self.inode {
            return Err(LinuxProjectQuotaError::FilesystemIdentity {
                path: self.path.clone(),
            });
        }
        Ok(())
    }

    fn verify_quota(&self) -> Result<(), LinuxProjectQuotaError> {
        validate_ext4_filesystem(&self.directory, &self.directory, &self.path)?;
        verify_assigned_project(&self.directory, &self.path, self.project_id)?;
        verify_project_quota(&self.directory, &self.path, self.project_id, self.limits)?;
        verify_project_usage_within_limit(&self.directory, &self.path, self.project_id, self.limits)
    }
}

impl AuditedProjectQuotaBinding {
    /// Audits a persistent quota under the caller's existing cooperative bounds.
    ///
    /// The caller reserves the complete audit peak before entry. An admission
    /// callback sees only verified filesystem/project identity and runs before
    /// namespace mutation. When `retain_uncertain_namespace` is true, failures
    /// after lease acquisition retain the actual lease and directory pin; the
    /// caller must also retain their original resource charge.
    ///
    /// # Errors
    /// Refuses invalid limits, failed quota identity or usage checks, an unsafe
    /// descendant, admission refusal or the caller's audit refusal. The latter
    /// carries only status; its concrete diagnostic remains with the caller.
    pub fn bind_existing_audited<A: QuotaAudit + ?Sized>(
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
        operation: &A,
        retain_uncertain_namespace: bool,
        admission: Option<ProjectAdmission<'_>>,
    ) -> Result<Self, LinuxProjectQuotaError> {
        Self::bind_existing_internal(
            root,
            project_id,
            maximum_physical_bytes,
            maximum_inodes,
            BindingScope {
                operation,
                retain_uncertain_namespace,
                admission,
            },
        )
    }

    fn bind_existing_internal<A: QuotaAudit + ?Sized>(
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
        mut scope: BindingScope<'_, '_, A>,
    ) -> Result<Self, LinuxProjectQuotaError> {
        let operation = scope.operation;
        if !project_id_is_supported(project_id) {
            return Err(LinuxProjectQuotaError::InvalidProjectId);
        }
        let limits = LinuxProjectQuotaLimits::new(maximum_physical_bytes, maximum_inodes)?;
        if !root.is_absolute()
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(LinuxProjectQuotaError::UnsafeNamespace {
                path: root.to_owned(),
            });
        }
        operation.check()?;
        let directory =
            descendants::open_root(root).map_err(|source| LinuxProjectQuotaError::Io {
                operation: "open-physical-quota-root",
                path: root.to_owned(),
                source: source.into(),
            })?;
        validate_ext4_filesystem(&directory, &directory, root)?;
        project_quota_info(&directory, root)?;
        verify_assigned_project(&directory, root, project_id)?;
        verify_project_quota(&directory, root, project_id, limits)?;
        verify_project_usage_within_limit(&directory, root, project_id, limits)?;
        let identity = fstat(&directory).map_err(|source| LinuxProjectQuotaError::Io {
            operation: "identify-physical-quota-root",
            path: root.to_owned(),
            source: source.into(),
        })?;
        if let Some(admission) = scope.admission.as_mut() {
            admission((identity.st_dev, project_id))?;
        }
        let namespace = match descendants::NamespaceLease::acquire(&directory, root, project_id) {
            Ok(namespace) => namespace,
            Err(error) => {
                if scope.retain_uncertain_namespace {
                    std::mem::forget(directory);
                }
                return Err(error);
            }
        };
        let checked = (|| {
            descendants::audit(&directory, root, project_id, maximum_inodes, operation)?;
            operation.check()?;
            verify_assigned_project(&directory, root, project_id)?;
            verify_project_quota(&directory, root, project_id, limits)?;
            verify_project_usage_within_limit(&directory, root, project_id, limits)?;
            Ok::<_, LinuxProjectQuotaError>(())
        })();
        if let Err(error) = checked {
            if scope.retain_uncertain_namespace {
                // The caller keeps the original resource account. Preserve the
                // actual lease too, so another owner cannot reopen uncertain
                // durable bytes while their first charge remains retained.
                std::mem::forget((directory, namespace));
            }
            return Err(error);
        }
        Ok(Self {
            binding: LinuxProjectQuotaBinding {
                directory,
                path: root.to_owned(),
                device: identity.st_dev,
                inode: identity.st_ino,
                project_id,
                limits,
            },
            namespace,
        })
    }

    /// Reauthenticates the pinned directory, quota, usage and any namespace lease.
    ///
    /// # Errors
    /// Refuses changed identity, assignment, limits, usage or namespace custody.
    pub fn verify(&self) -> Result<(), LinuxProjectQuotaError> {
        self.verify_authority()
    }

    /// Creates a bounded directory chain beneath this authenticated namespace.
    ///
    /// The same caller-owned audit checks each step. Paths cannot escape the
    /// pinned root, cross mounts or symlinks, or exceed sixteen components.
    ///
    /// # Errors
    /// Refuses changed quota authority, unsafe paths or entries, kernel errors
    /// or the caller's retained audit refusal.
    pub fn prepare_descendant_directory_under<A: QuotaAudit + ?Sized>(
        &self,
        path: &Path,
        operation: &A,
    ) -> Result<(), LinuxProjectQuotaError> {
        self.verify_authority()?;
        descendants::prepare_directory(
            &self.binding.directory,
            &self.binding.path,
            path,
            self.binding.project_id,
            operation,
        )?;
        self.verify_authority()
    }

    /// Returns the full audit's maximum simultaneously open descriptor count.
    #[must_use]
    pub const fn maximum_audit_file_descriptors() -> u64 {
        36
    }

    /// Returns the full audit's maximum bounded directory scan scratch bytes.
    #[must_use]
    pub const fn maximum_audit_scratch_bytes() -> u64 {
        17 * 4096
    }

    fn verify_authority(&self) -> Result<(), LinuxProjectQuotaError> {
        let current = descendants::open_root(&self.binding.path).map_err(|source| {
            LinuxProjectQuotaError::Io {
                operation: "reopen-physical-quota-root",
                path: self.binding.path.clone(),
                source: source.into(),
            }
        })?;
        self.binding.verify_identity(&current)?;
        self.namespace.verify(
            &self.binding.directory,
            &self.binding.path,
            self.binding.project_id,
        )?;
        self.binding.verify_quota()
    }
}

#[cfg(test)]
mod tests;

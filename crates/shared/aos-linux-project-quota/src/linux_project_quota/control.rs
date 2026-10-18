//! Retains weak, monotonic tightening authority for one live project reservation.
//!
//! Controllers share the reservation's pinned descriptors and cannot release
//! quotas or reuse project identifiers. Retirement closes admission under the
//! same mutex used for kernel updates before quota clearing can begin.

use super::*;
use std::sync::{Arc, Mutex, Weak};

#[derive(Debug)]
pub(super) struct QuotaControlState {
    filesystem: Arc<OwnedFd>,
    directory: Arc<OwnedFd>,
    path: PathBuf,
    project_id: u32,
    limits: LinuxProjectQuotaLimits,
    active: bool,
    failed: bool,
}

/// Weak authority to reduce one retained project quota without releasing it.
#[derive(Clone, Debug)]
pub struct LinuxProjectQuotaController {
    state: Weak<Mutex<QuotaControlState>>,
}

impl LinuxProjectQuotaController {
    /// Tightens aggregate bytes while preserving the initial inode ceiling.
    ///
    /// The same live reservation serializes updates and retirement. Requests
    /// may retain or reduce the current ceiling; an increase is refused before
    /// any kernel write. A partial kernel failure permanently closes updates.
    ///
    /// # Errors
    /// Returns an error for retired authority, an increased or invalid ceiling,
    /// stale directory/quota identity, usage above the new ceiling, or failed
    /// kernel installation, synchronization, or read-back verification.
    pub fn tighten(&self, maximum_writable_bytes: u64) -> Result<(), LinuxProjectQuotaError> {
        let state = self
            .state
            .upgrade()
            .ok_or(LinuxProjectQuotaError::RetiredController)?;
        let mut state = state
            .lock()
            .map_err(|_| LinuxProjectQuotaError::RetiredController)?;
        if !state.active || state.failed {
            return Err(LinuxProjectQuotaError::RetiredController);
        }
        let next =
            LinuxProjectQuotaLimits::new(maximum_writable_bytes, state.limits.maximum_inodes())?;
        if next.requested_bytes() > state.limits.requested_bytes() {
            return Err(LinuxProjectQuotaError::LimitIncrease);
        }
        if let Err(error) = state.install_tightened(next) {
            state.failed = true;
            return Err(error);
        }
        state.limits = next;
        Ok(())
    }
}

impl QuotaControlState {
    fn install_tightened(
        &self,
        next: LinuxProjectQuotaLimits,
    ) -> Result<(), LinuxProjectQuotaError> {
        validate_ext4_filesystem(&self.filesystem, &self.directory, &self.path)?;
        verify_assigned_project(&self.directory, &self.path, self.project_id)?;
        verify_project_quota(&self.filesystem, &self.path, self.project_id, self.limits)?;
        verify_project_usage_within_limit(&self.filesystem, &self.path, self.project_id, next)?;
        set_project_quota(&self.filesystem, &self.path, self.project_id, next)?;
        sync_project_quota(&self.filesystem, &self.path)?;
        verify_project_quota(&self.filesystem, &self.path, self.project_id, next)?;
        verify_project_usage_within_limit(&self.filesystem, &self.path, self.project_id, next)
    }
}

impl LinuxProjectQuotaReservation {
    /// Lends weak tightening authority tied to this exact live reservation.
    ///
    /// The controller shares pinned descriptors without duplicating them. It
    /// cannot survive reservation retirement, even if a later allocation reuses
    /// the same numeric project identifier.
    ///
    /// # Errors
    /// Returns an error when descriptors were released or control was retired.
    pub fn controller(&mut self) -> Result<LinuxProjectQuotaController, LinuxProjectQuotaError> {
        if self.released {
            return Err(LinuxProjectQuotaError::RetiredController);
        }
        if self.control.is_none() {
            self.control = Some(Arc::new(Mutex::new(QuotaControlState {
                filesystem: self
                    .filesystem
                    .as_ref()
                    .ok_or(LinuxProjectQuotaError::RetiredController)?
                    .clone(),
                directory: self
                    .directory
                    .as_ref()
                    .ok_or(LinuxProjectQuotaError::RetiredController)?
                    .clone(),
                path: self.path.clone(),
                project_id: self.project_id,
                limits: self.limits,
                active: true,
                failed: false,
            })));
        }
        let state = self
            .control
            .as_ref()
            .ok_or(LinuxProjectQuotaError::RetiredController)?;
        let live = state
            .lock()
            .map_err(|_| LinuxProjectQuotaError::RetiredController)?;
        if !live.active || live.failed {
            return Err(LinuxProjectQuotaError::RetiredController);
        }
        drop(live);
        Ok(LinuxProjectQuotaController {
            state: Arc::downgrade(state),
        })
    }

    pub(super) fn current_control_limits(
        &self,
    ) -> Result<LinuxProjectQuotaLimits, LinuxProjectQuotaError> {
        match &self.control {
            Some(control) => control
                .lock()
                .map(|state| state.limits)
                .map_err(|_| LinuxProjectQuotaError::RetiredController),
            None => Ok(self.limits),
        }
    }

    pub(super) fn retire_controller(&self) {
        if let Some(control) = &self.control {
            let mut state = control
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.active = false;
        }
    }
}

#[cfg(test)]
mod tests {
    //! Checks stale weak authority and validation before any privileged effect.
    use super::*;

    fn state() -> Arc<Mutex<QuotaControlState>> {
        let descriptor: OwnedFd = std::fs::File::open("/dev/null")
            .unwrap_or_else(|error| panic!("open non-quota fixture: {error}"))
            .into();
        let descriptor = Arc::new(descriptor);
        Arc::new(Mutex::new(QuotaControlState {
            filesystem: descriptor.clone(),
            directory: descriptor,
            path: PathBuf::from("/dev/null"),
            project_id: 1,
            limits: LinuxProjectQuotaLimits::new(8192, 16)
                .unwrap_or_else(|error| panic!("construct quota ceiling: {error}")),
            active: true,
            failed: false,
        }))
    }

    #[test]
    fn increases_fail_before_kernel_access_and_cannot_change_ceiling() {
        let state = state();
        let controller = LinuxProjectQuotaController {
            state: Arc::downgrade(&state),
        };
        assert!(matches!(
            controller.tighten(8193),
            Err(LinuxProjectQuotaError::LimitIncrease)
        ));
        let state = state
            .lock()
            .unwrap_or_else(|error| panic!("inspect quota state: {error}"));
        assert_eq!(state.limits.requested_bytes(), 8192);
        assert!(!state.failed);
    }

    #[test]
    fn uncertain_validation_is_sticky_and_does_not_authorize_a_later_update() {
        let state = state();
        let controller = LinuxProjectQuotaController {
            state: Arc::downgrade(&state),
        };
        assert!(controller.tighten(4096).is_err());
        assert!(matches!(
            controller.tighten(8192),
            Err(LinuxProjectQuotaError::RetiredController)
        ));
    }

    #[test]
    fn retired_and_reallocated_numeric_projects_have_independent_authority() {
        let old = state();
        let controller = LinuxProjectQuotaController {
            state: Arc::downgrade(&old),
        };
        old.lock()
            .unwrap_or_else(|error| panic!("retire old quota: {error}"))
            .active = false;
        let replacement = state();
        assert_eq!(
            old.lock()
                .unwrap_or_else(|error| panic!("inspect old quota: {error}"))
                .project_id,
            replacement
                .lock()
                .unwrap_or_else(|error| panic!("inspect new quota: {error}"))
                .project_id
        );
        assert!(matches!(
            controller.tighten(4096),
            Err(LinuxProjectQuotaError::RetiredController)
        ));
        drop(old);
        assert!(matches!(
            controller.tighten(4096),
            Err(LinuxProjectQuotaError::RetiredController)
        ));
        assert!(
            replacement
                .lock()
                .unwrap_or_else(|error| panic!("inspect replacement: {error}"))
                .active
        );
    }
}

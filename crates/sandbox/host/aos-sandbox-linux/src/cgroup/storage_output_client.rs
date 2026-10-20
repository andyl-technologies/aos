//! Retains the fixed Storage/init.scope resolution through an existing root.
//!
//! These are native DATA observations, not a service, root or output grant.
//! The actual Host catalog retains its original root throughout acquisition.

use super::*;

/// Retains the two fixed client anchors and every reached native prefix.
#[derive(Debug, Default)]
pub struct StorageOutputClientCgroupOriginalV2 {
    storage: InitialCgroupChildV5,
    manager: InitialCgroupChildV5,
    storage_active: PendingRegularFileV1,
    manager_active: PendingRegularFileV1,
    result: Option<Result<()>>,
    entered: bool,
    taken: bool,
    positive_prefix_disposed: bool,
}

impl StorageOutputClientCgroupOriginalV2 {
    /// Creates empty DATA destinations without native IO.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Resolves only the compiled Storage service and PID1 manager names.
    ///
    /// # Errors
    /// Retains the actual first native failure and all reached descriptors.
    /// Reentry refuses without replacing any earlier cause or prefix.
    pub fn capture_once(&mut self, root: &CgroupV2Root) -> Result<()> {
        if self.entered { return Err(closed()); }
        self.entered = true;
        self.result = Some(self.capture_recipe(root));
        if matches!(self.result, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }

    fn capture_recipe(&mut self, root: &CgroupV2Root) -> Result<()> {
        root.anchor.resolve_initial_service_retaining(&mut self.storage, InitialServiceCgroupV1::Storage)?;
        root.anchor.resolve_initial_service_retaining(&mut self.manager, InitialServiceCgroupV1::StorageManager)?;
        self.storage.anchor.as_ref().ok_or_else(closed)?
            .validate_active_retaining(&mut self.storage_active)?;
        self.manager.anchor.as_ref().ok_or_else(closed)?
            .validate_active_retaining(&mut self.manager_active)
    }

    /// Moves the same complete pair once, retaining its native observations.
    #[must_use]
    pub fn take_completed_pair_once(&mut self) -> Option<(RetainedCgroupAnchor, RetainedCgroupAnchor)> {
        self.take_pair_engine_v5(false)
    }

    /// Moves the same complete pair after physically closing its local probes.
    ///
    /// Both real anchors remain owned by the returned client. Every constructor
    /// check and active bookend must already be positive; an incomplete or failed
    /// original keeps every descriptor and cannot return a pair through this cut.
    #[must_use]
    pub fn take_pair_retiring_positive_prefix_v5(&mut self)
        -> Option<(RetainedCgroupAnchor, RetainedCgroupAnchor)> {
        self.take_pair_engine_v5(true)
    }

    fn take_pair_engine_v5(&mut self, retire: bool)
        -> Option<(RetainedCgroupAnchor, RetainedCgroupAnchor)> {
        if self.taken || !matches!(self.result, Some(Ok(()))) { return None; }
        if self.storage.anchor.is_none() || self.manager.anchor.is_none() { return None; }
        if retire {
            if self.positive_prefix_disposed || self.storage.probes.iter().chain(&self.manager.probes)
                .any(|probe| probe.file().is_err())
                || self.storage_active.file().is_err() || self.manager_active.file().is_err()
            { return None; }
            // All checks precede any owning drop. The anchors stay in their
            // original slots until every completed temporary file has retired.
            for probe in self.storage.probes.iter_mut().chain(&mut self.manager.probes) {
                drop(probe.take_readable_file());
            }
            drop(self.storage_active.take_readable_file());
            drop(self.manager_active.take_readable_file());
            self.positive_prefix_disposed = true;
        }
        self.taken = true;
        match (self.storage.anchor.take(), self.manager.anchor.take()) {
            (Some(storage), Some(manager)) => Some((storage, manager)),
            _ => std::process::abort(),
        }
    }

    /// Reports actual positive constructor-file disposal without granting a role.
    #[must_use]
    pub fn positive_prefix_is_disposed_v5(&self) -> bool {
        self.positive_prefix_disposed && self.taken && matches!(self.result, Some(Ok(())))
    }

    /// Borrows the actual first reached failure without observing again.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> { self.result.as_ref()?.as_ref().err() }

    /// Returns fixed compiled bytes, native descriptor and namespace bounds.
    ///
    /// No amount returned by this DATA supplier authorizes native entry.
    #[must_use]
    pub fn receiving_demand_v2() -> Option<(usize, usize, usize)> {
        let paths = InitialServiceCgroupV1::Storage.relative().as_os_str().len()
            .checked_add(InitialServiceCgroupV1::StorageManager.relative().as_os_str().len())?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(paths.checked_mul(8)?)?.checked_add(8 * 4096)?;
        // Each fixed child has a pending resolution, anchor and three probes;
        // the two final active probes remain independent native destinations.
        Some((bytes, 12, 6))
    }
}

fn closed() -> Error { Error::invalid("Storage output client cgroup", "original already entered or refused") }

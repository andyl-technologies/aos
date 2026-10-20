//! Retains generic cgroup native acquisition and bounded freezer-read prefixes.
//!
//! These objects run the existing kernel engines and supply no service role,
//! launch proof, payer or authority. Genuine callers retain their own entered
//! operation and independently owed posts beside these native originals.

use super::*;
use std::os::fd::AsFd as _;
use std::os::unix::fs::FileExt as _;


/// Keeps an owned cgroup candidate through root and active-file validation.
#[derive(Debug, Default)]
pub struct CgroupRootOriginalV2 {
    root: PendingBeneathRootV5,
    anchor: Option<RetainedCgroupAnchor>,
    probe: PendingRegularFileV1,
    returned: Option<Result<()>>,
    entered: bool,
    closed: Option<Error>,
    completed_identity: Option<crate::path::FileIdentity>,
    disposed_identity: Option<crate::path::FileIdentity>,
}

impl CgroupRootOriginalV2 {
    /// Creates empty destinations without adopting or inspecting a descriptor.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Runs the same root, filesystem, identity and active-reference checks.
    ///
    /// # Errors
    /// Keeps the exact original descriptor and every reached native refusal.
    /// Reentry cannot resample or replace any original.
    pub fn admit_once(&mut self, descriptor: OwnedFd) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.returned = Some((|| {
            self.root.retain(descriptor)?;
            let root = self.root.take_validated().ok_or_else(closed)?;
            self.validate_beneath(root)
        })());
        if matches!(self.returned, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }

    /// Parks the same already-validated root before cgroup-specific checks.
    ///
    /// This matches `CgroupV2Root::try_from` without repeating owned-root
    /// CLOEXEC/fstat observations or duplicating the actual descriptor.
    ///
    /// # Errors
    /// Retains the original root, probe and exact cgroup validation failure.
    pub fn from_beneath_once(&mut self, root: BeneathRoot) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.returned = Some(self.validate_beneath(root));
        if matches!(self.returned, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }

    fn validate_beneath(&mut self, root: BeneathRoot) -> Result<()> {
        self.anchor = Some(anchor_from_root!(root));
        self.anchor.as_ref().ok_or_else(closed)?.validate_initial_retaining(&mut self.probe)
    }

    /// Moves the same fully validated cgroup root once; probes stay resident.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<CgroupV2Root> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) { return None; }
        let anchor = self.anchor.take()?;
        self.completed_identity = Some(anchor.root.identity());
        Some(CgroupV2Root { anchor })
    }

    /// Closes complete admission probes after moving the actual root out.
    ///
    /// The separately held root must carry the exact moved native identity.
    /// Failure, reentry, partial admission and repeated disposal retain their
    /// prefixes. This historical mechanical proof grants no currentness.
    #[must_use]
    pub fn retire_completed_prefix_once_v4(&mut self, root: &CgroupV2Root) -> bool {
        if !matches!(self.returned, Some(Ok(()))) || self.failure().is_some()
            || self.anchor.is_some() || self.probe.file().is_err()
            || self.disposed_identity.is_some()
            || self.completed_identity != Some(root.anchor.root.identity())
        {
            return false;
        }
        drop(self.probe.take_readable_file());
        self.disposed_identity = self.completed_identity;
        true
    }

    /// Reports actual probe retirement for this exact completed root original.
    #[must_use]
    pub fn completed_prefix_is_disposed_v4(&self) -> bool {
        self.disposed_identity.is_some() && self.disposed_identity == self.completed_identity
            && self.failure().is_none()
    }

    /// Borrows the actual first validation error.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.returned.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Bounds the candidate, active probe, fixed pathname and native carriers.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(2 * 13)?, 2, 1))
    }
}

/// Keeps a strict child resolution and all three active-reference probes.
#[derive(Debug, Default)]
pub struct CgroupChildOriginalV2 {
    child: InitialCgroupChildV5,
    returned: Option<Result<()>>,
    entered: bool,
    closed: Option<Error>,
    completed_identity: Option<crate::path::FileIdentity>,
    disposed_identity: Option<crate::path::FileIdentity>,
}

impl CgroupChildOriginalV2 {
    /// Creates empty native destinations without resolving a child.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Resolves the same exact relative child through the existing engine.
    ///
    /// # Errors
    /// Retains strict resolution, cgroup identity and active-file failures.
    pub fn resolve_once(&mut self, root: &CgroupV2Root, relative: &Path) -> Result<()> {
        self.capture(&root.anchor, relative, false)
    }

    /// Resolves a proper descendant with the existing descendant-hint check.
    ///
    /// # Errors
    /// Retains invalid hints and the same native child/probe failure prefix.
    pub fn resolve_descendant_once(&mut self, anchor: &RetainedCgroupAnchor, relative: &Path) -> Result<()> {
        self.capture(anchor, relative, true)
    }

    fn capture(&mut self, anchor: &RetainedCgroupAnchor, relative: &Path, descendant: bool) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        let pending = &mut self.child;
        self.returned = Some((|| {
            if descendant { validate_descendant_hint(relative)?; }
            resolve_child_recipe!(anchor, relative, Retained, pending)
        })());
        if matches!(self.returned, Some(Ok(()))) { Ok(()) } else { Err(closed()) }
    }

    /// Moves only the actual completed child; all independent probes remain held.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<RetainedCgroupAnchor> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) { return None; }
        let anchor = self.child.anchor.take()?;
        self.completed_identity = Some(anchor.root.identity());
        Some(anchor)
    }

    /// Closes completed resolution probes after moving the actual child out.
    ///
    /// The caller finishes any required output-identity comparison first and
    /// retains the exact moved child separately. All native Results and the
    /// once fence remain; a failed or partial resolver cannot retire.
    #[must_use]
    pub fn retire_completed_prefix_once_v4(&mut self, anchor: &RetainedCgroupAnchor) -> bool {
        if !matches!(self.returned, Some(Ok(()))) || self.failure().is_some()
            || self.child.anchor.is_some()
            || self.child.probes.iter().any(|probe| probe.file().is_err())
            || self.disposed_identity.is_some()
            || self.completed_identity != Some(anchor.root.identity())
        {
            return false;
        }
        for probe in &mut self.child.probes {
            drop(probe.take_readable_file());
        }
        self.disposed_identity = self.completed_identity;
        true
    }

    /// Reports actual probe retirement for this exact moved child original.
    #[must_use]
    pub fn completed_prefix_is_disposed_v4(&self) -> bool {
        self.disposed_identity.is_some() && self.disposed_identity == self.completed_identity
            && self.failure().is_none()
    }

    /// Borrows the actual first child/hint/native failure.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.returned.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Bounds one child, three real probes, path bytes and opened name entries.
    #[must_use]
    pub fn receiving_obligations_v2(path_bytes: usize) -> Option<(usize, usize, usize)> {
        if path_bytes > 4096 { return None; }
        let paths = path_bytes.checked_add(1)?.checked_mul(2)?.checked_add(6 * 13)?;
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(paths)?, 4, 3))
    }
}

/// Retains one exact existing freezer read, including partial bytes and Files.
#[derive(Debug)]
pub struct FreezerReadOriginalV2 {
    pub(super) probe: PendingRegularFileV1,
    pub(super) active: Option<Result<()>>,
    pub(super) events: PendingRegularFileV1,
    pub(super) opened: Option<Result<()>>,
    pub(super) file: Option<File>,
    pub(super) bytes: [u8; 4097],
    pub(super) read: Option<std::io::Result<usize>>,
    returned: Option<Result<CgroupFreezerState>>,
    entered: bool,
    taken: bool,
    closed: Option<Error>,
}

impl FreezerReadOriginalV2 {
    /// Creates empty native destinations and the fixed existing bounded buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            probe: PendingRegularFileV1::default(), active: None,
            events: PendingRegularFileV1::default(), opened: None, file: None,
            bytes: [0; 4097], read: None, returned: None,
            entered: false, taken: false, closed: None,
        }
    }

    /// Executes the same active/open/read/length/parser sequence once.
    ///
    /// # Errors
    /// Keeps actual native descriptors, partial bytes and the first read/parse
    /// cause. Reentry cannot observe again or replace a completed result.
    pub fn observe_once(&mut self, anchor: &RetainedCgroupAnchor) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.returned = Some((|| { freezer_recipe!(anchor, Retained, self) })());
        if matches!(self.returned, Some(Ok(_))) { Ok(()) } else { Err(closed()) }
    }

    /// Takes only the actual parsed state DATA once, leaving native originals held.
    #[must_use]
    pub fn take_completed_once(&mut self) -> Option<CgroupFreezerState> {
        if self.taken || self.closed.is_some() { return None; }
        let state = self.returned.as_ref()?.as_ref().ok().copied()?;
        self.taken = true;
        Some(state)
    }

    /// Borrows the first exact native, read or parser failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.active).or_else(|| error(&self.opened)).or_else(|| error(&self.read))
            .or_else(|| error(&self.returned)).or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Bounds the fixed native buffer, two Files and two fixed control names.
    #[must_use]
    pub fn receiving_obligations_v2() -> Option<(usize, usize, usize)> {
        Some((std::mem::size_of::<Self>().checked_mul(2)?.checked_add(2 * (13 + 14))?, 2, 2))
    }
}

impl Default for FreezerReadOriginalV2 {
    fn default() -> Self { Self::new() }
}

pub(super) fn closed() -> Error {
    Error::invalid("retained cgroup operation", "original operation remains closed")
}

fn error<T, E: std::error::Error + 'static>(slot: &Option<std::result::Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_root_and_child_probes_retire_after_the_same_real_outputs_move() {
        let descriptor = rustix::fs::open("/sys/fs/cgroup",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        let mut original = CgroupRootOriginalV2::new();
        original.admit_once(descriptor).unwrap();
        let root = original.take_completed_once().unwrap();
        assert!(original.probe.file().is_ok());

        assert!(original.retire_completed_prefix_once_v4(&root));
        assert!(original.completed_prefix_is_disposed_v4());
        assert!(original.probe.file().is_err());
        assert!(uapi::fstat(root.anchor.as_fd()).is_ok());
        assert!(!original.retire_completed_prefix_once_v4(&root));
        let mut child = CgroupChildOriginalV2::new();
        child.resolve_once(&root, Path::new(".")).unwrap();
        let anchor = child.take_completed_once().unwrap();
        assert!(child.child.probes.iter().all(|probe| probe.file().is_ok()));

        assert!(child.retire_completed_prefix_once_v4(&anchor));
        assert!(child.completed_prefix_is_disposed_v4());
        assert!(child.child.probes.iter().all(|probe| probe.file().is_err()));
        assert!(uapi::fstat(anchor.as_fd()).is_ok());
        assert!(!child.retire_completed_prefix_once_v4(&anchor));
    }

    #[test]
    fn non_cgroup_directory_keeps_original_root_and_actual_first_error() {
        let directory = tempfile::tempdir().unwrap();
        let descriptor = rustix::fs::open(directory.path(), rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        let mut original = CgroupRootOriginalV2::new();
        assert!(original.admit_once(descriptor).is_err());
        let first = original.failure().unwrap() as *const Error;
        let anchor = original.anchor.as_ref().unwrap();
        assert!(uapi::fstat(anchor.as_fd()).is_ok());

        let other = rustix::fs::open(directory.path(), rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty()).unwrap();
        assert!(original.admit_once(other).is_err());
        assert_eq!(original.failure().unwrap() as *const Error, first);
        assert!(uapi::fstat(original.anchor.as_ref().unwrap().as_fd()).is_ok());
        assert!(original.take_completed_once().is_none());
        assert!(!original.completed_prefix_is_disposed_v4());
    }
}

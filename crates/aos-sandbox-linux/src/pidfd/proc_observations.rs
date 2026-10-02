//! Bounded original procfs descriptors observed under an actual retained pidfd.
//!
//! The reservoir parks stat and context descriptors before inspecting or reading
//! them. Continued observations rewind those same descriptors; they never open
//! a child pathname again. This is nonauthorizing DATA: its owner must retain and
//! supply the same original pidfd, authenticate its role and apply current policy.
//! Err, incomplete capture and caught unwind permanently close the reservoir.

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::MetadataExt as _;

use rustix::fs::{Mode, OFlags, fcntl_getfl, fstatfs, open};

use super::identity::{MAXIMUM_PROC_STAT_BYTES, identity_from_stat, parse_proc_stat};
use super::{PidFd, PidFdInfo, PidFdProcessIdentity};
use crate::{Error, Result};

const PROCFS_MAGIC: u64 = 0x9fa0;
const CONTEXT_BYTES: usize = 256;
const READ_INTERRUPT_LIMIT: usize = 8;
const NIX_HELPER_STATUS_BYTES: usize = 64 * 1024;
const NIX_HELPER_MAPS_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservationPhaseV1 {
    Fresh,
    StatCaptured,
    Ready,
    Closed,
}

#[derive(Clone, Copy)]
enum ProcFileV1 {
    Stat,
    Context,
    NixHelperStatus,
    NixHelperMaps,
}

impl ProcFileV1 {
    const fn suffix(self) -> &'static str {
        match self {
            Self::Stat => "stat",
            Self::Context => "attr/current",
            Self::NixHelperStatus => "status",
            Self::NixHelperMaps => "maps",
        }
    }

    const fn maximum(self) -> usize {
        match self {
            Self::Stat => MAXIMUM_PROC_STAT_BYTES,
            Self::Context => CONTEXT_BYTES,
            Self::NixHelperStatus => NIX_HELPER_STATUS_BYTES,
            Self::NixHelperMaps => NIX_HELPER_MAPS_BYTES,
        }
    }
}

struct NixHelperOriginalsV1 {
    status: ProcDescriptorV1,
    executable: Option<File>,
    executable_identity: Option<(u64, u64, u64)>,
    maps: ProcDescriptorV1,
    captured: bool,
}

impl NixHelperOriginalsV1 {
    const fn empty() -> Self {
        Self {
            status: ProcDescriptorV1::empty(),
            executable: None,
            executable_identity: None,
            maps: ProcDescriptorV1::empty(),
            captured: false,
        }
    }
}

struct ProcDescriptorV1 {
    file: Option<File>,
    initial: Vec<u8>,
    current: Vec<u8>,
}

impl ProcDescriptorV1 {
    const fn empty() -> Self {
        Self {
            file: None,
            initial: Vec::new(),
            current: Vec::new(),
        }
    }

    fn capture(&mut self, pid: u32, kind: ProcFileV1) -> Result<()> {
        let path = format!("/proc/{pid}/{}", kind.suffix());
        let descriptor = open(
            path.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| Error::Syscall {
            operation: "open(original proc observation)",
            source: source.into(),
        })?;

        // No fallible operation follows receipt before this actual owner slot.
        self.file = Some(File::from(descriptor));
        let file = self.file.as_ref().ok_or_else(closed)?;
        let filesystem = fstatfs(file).map_err(|source| Error::Syscall {
            operation: "fstatfs(original proc observation)",
            source: source.into(),
        })?;
        let flags = fcntl_getfl(file).map_err(|source| Error::Syscall {
            operation: "fcntl(original proc observation)",
            source: source.into(),
        })?;
        if filesystem.f_type as u64 != PROCFS_MAGIC
            || flags & OFlags::ACCMODE != OFlags::RDONLY
            || flags.contains(OFlags::PATH)
        {
            return Err(Error::invalid("proc observation", "descriptor is not read-only procfs"));
        }

        self.read(kind.maximum())?;
        self.initial.try_reserve_exact(self.current.len()).map_err(|_| {
            Error::invalid("proc observation", "bounded initial-byte allocation failed")
        })?;
        self.initial.extend_from_slice(&self.current);
        Ok(())
    }

    fn read(&mut self, maximum: usize) -> Result<()> {
        // The fixed extra byte distinguishes exact EOF from an oversized read.
        // Failed partial bytes remain in current; successful earlier reads are
        // not advertised as a complete observation history.
        self.current.clear();
        let bound = maximum.checked_add(1).ok_or_else(closed)?;
        self.current.try_reserve_exact(bound).map_err(|_| {
            Error::invalid("proc observation", "bounded read allocation failed")
        })?;
        let file = self.file.as_mut().ok_or_else(closed)?;
        file.seek(SeekFrom::Start(0)).map_err(|source| Error::Syscall {
            operation: "rewind(original proc observation)",
            source,
        })?;

        let mut scratch = [0_u8; 256];
        let mut interrupted = 0;
        while self.current.len() < bound {
            let available = (bound - self.current.len()).min(scratch.len());
            let count = match file.read(&mut scratch[..available]) {
                Ok(count) => count,
                Err(source) if source.kind() == std::io::ErrorKind::Interrupted
                    && interrupted < READ_INTERRUPT_LIMIT =>
                {
                    interrupted += 1;
                    continue;
                }
                Err(source) => return Err(Error::Syscall {
                    operation: "read(original proc observation)",
                    source,
                }),
            };
            if count == 0 {
                return Ok(());
            }
            self.current.extend_from_slice(&scratch[..count]);
            interrupted = 0;
        }

        Err(Error::invalid("proc observation", "record exceeds its fixed bound"))
    }
}

/// Retains bounded stat/context descriptor DATA without granting process authority.
///
/// Construction is available only through a named method on an actual pidfd.
/// No descriptor, pathname, role, caller maximum or observation setter is exposed.
/// Its purpose owner must keep supplying that same original pin. The reservoir
/// is neither an image/subject proof nor a snapshot across time or process exit.
pub struct PidFdProcObservationsV1 {
    stat: ProcDescriptorV1,
    context: ProcDescriptorV1,
    original_info: Option<PidFdInfo>,
    original_identity: Option<PidFdProcessIdentity>,
    phase: ObservationPhaseV1,
    nix_helper: Option<NixHelperOriginalsV1>,
}

impl PidFd {
    /// Prepares empty nonauthorizing slots before original procfs acquisition.
    #[must_use]
    pub fn prepare_proc_observations_v1(&self) -> PidFdProcObservationsV1 {
        PidFdProcObservationsV1 {
            stat: ProcDescriptorV1::empty(),
            context: ProcDescriptorV1::empty(),
            original_info: None,
            original_identity: None,
            phase: ObservationPhaseV1::Fresh,
            nix_helper: None,
        }
    }
}

impl PidFdProcObservationsV1 {
    /// Parks fixed Nix helper status, executable and maps originals before HELLO.
    ///
    /// This selected DATA capture follows the ordinary stat/context capture on
    /// the same actual pidfd. Every returned descriptor remains resident before
    /// metadata, reads or postchecks. No pathname, FD, role or bound is supplied.
    /// Full loader, executable and purpose checks belong to the genuine owner.
    ///
    /// # Errors
    /// Permanently fences repeated capture, changed/exited processes, failed
    /// original opens/reads or oversized records. Partial files and bytes stay.
    pub fn capture_nix_offline_helper_originals_v1(&mut self, original: &PidFd) -> Result<()> {
        let operation = self.begin(ObservationPhaseV1::Ready)?;
        let result = operation.observations.capture_nix_helper_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)
    }

    fn capture_nix_helper_inner(&mut self, original: &PidFd) -> Result<()> {
        if self.nix_helper.is_some() {
            return Err(closed());
        }
        self.nix_helper = Some(NixHelperOriginalsV1::empty());
        let before = self.require_original_info(original)?;
        self.nix_helper.as_mut().ok_or_else(closed)?.status
            .capture(before.pid(), ProcFileV1::NixHelperStatus)?;
        self.require_original_info(original)?;

        let path = format!("/proc/{}/exe", before.pid());
        let descriptor = open(path.as_str(), OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .map_err(|source| Error::Syscall {
                operation: "open(original Nix helper executable)",
                source: source.into(),
            })?;
        self.nix_helper.as_mut().ok_or_else(closed)?.executable = Some(File::from(descriptor));
        let helper = self.nix_helper.as_mut().ok_or_else(closed)?;
        let file = helper.executable.as_ref().ok_or_else(closed)?;
        let flags = fcntl_getfl(file).map_err(|source| Error::Syscall {
            operation: "fcntl(original Nix helper executable)",
            source: source.into(),
        })?;
        let metadata = file.metadata().map_err(|source| Error::Syscall {
            operation: "stat(original Nix helper executable)", source,
        })?;
        if !metadata.is_file() || flags & OFlags::ACCMODE != OFlags::RDONLY
            || flags.contains(OFlags::PATH)
        {
            return Err(Error::invalid("Nix helper executable", "original is not a readable regular file"));
        }
        helper.executable_identity = Some((metadata.dev(), metadata.ino(), metadata.len()));
        self.require_original_info(original)?;
        self.nix_helper.as_mut().ok_or_else(closed)?.maps
            .capture(before.pid(), ProcFileV1::NixHelperMaps)?;
        self.require_original_info(original)?;
        self.nix_helper.as_mut().ok_or_else(closed)?.captured = true;
        Ok(())
    }

    /// Borrows bounded pre-HELLO maps DATA from the original completed capture.
    ///
    /// # Errors
    /// Rejects uncompleted/failed capture. This does not reread maps after ACK.
    pub fn nix_offline_helper_maps_v1(&self) -> Result<&[u8]> {
        let helper = self.nix_helper.as_ref().ok_or_else(closed)?;
        if self.phase != ObservationPhaseV1::Ready || !helper.captured {
            return Err(closed());
        }
        Ok(&helper.maps.initial)
    }

    /// Compares the original executable descriptor under the same retained pidfd.
    ///
    /// Returned device/inode/length is DATA for the genuine image comparator;
    /// neither a received tuple nor historical maps can admit this observation.
    ///
    /// # Errors
    /// Fences absent measurement, changed metadata, original process or liveness.
    pub fn observe_nix_offline_helper_executable_v1(
        &mut self,
        original: &PidFd,
    ) -> Result<(u64, u64, u64)> {
        let operation = self.begin(ObservationPhaseV1::Ready)?;
        let result = operation.observations.observe_nix_helper_executable_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)
    }

    fn observe_nix_helper_executable_inner(&self, original: &PidFd) -> Result<(u64, u64, u64)> {
        self.require_original_info(original)?;
        let helper = self.nix_helper.as_ref().ok_or_else(closed)?;
        if !helper.captured {
            return Err(closed());
        }
        let metadata = helper.executable.as_ref().ok_or_else(closed)?.metadata()
            .map_err(|source| Error::Syscall {
                operation: "stat(original Nix helper executable)", source,
            })?;
        let observed = (metadata.dev(), metadata.ino(), metadata.len());
        if Some(observed) != helper.executable_identity {
            return Err(Error::invalid("Nix helper executable", "original inode changed"));
        }
        self.require_original_info(original)?;
        Ok(observed)
    }

    /// Rereads bounded Nix helper status from the same zero-offset descriptor.
    ///
    /// This can be used after nondumpable ACK without reopening a proc name.
    /// Capability/NNP matching is purpose-local; bytes alone grant nothing.
    ///
    /// # Errors
    /// Fences absent measurement, failed reread or changed/exited original task.
    pub fn observe_nix_offline_helper_status_v1(&mut self, original: &PidFd) -> Result<&[u8]> {
        let operation = self.begin(ObservationPhaseV1::Ready)?;
        let result = operation.observations.observe_nix_helper_status_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)?;
        Ok(&self.nix_helper.as_ref().ok_or_else(closed)?.status.current)
    }

    fn observe_nix_helper_status_inner(&mut self, original: &PidFd) -> Result<()> {
        self.require_original_info(original)?;
        let helper = self.nix_helper.as_mut().ok_or_else(closed)?;
        if !helper.captured {
            return Err(closed());
        }
        helper.status.read(NIX_HELPER_STATUS_BYTES)?;
        self.require_original_info(original)?;
        Ok(())
    }

    /// Captures stat once under the owner's same original pidfd.
    ///
    /// # Errors
    /// Rejects closed/repeated capture, procfs denial or malformed/oversized stat,
    /// changed GET_INFO facts, and process exit. Partial custody stays owned.
    pub fn capture_stat(&mut self, original: &PidFd) -> Result<PidFdProcessIdentity> {
        let operation = self.begin(ObservationPhaseV1::Fresh)?;
        let result = operation.observations.capture_stat_inner(original);
        operation.finish(result, ObservationPhaseV1::StatCaptured)
    }

    fn capture_stat_inner(&mut self, original: &PidFd) -> Result<PidFdProcessIdentity> {
        let before = original.info()?;
        self.original_info = Some(before);
        self.stat.capture(before.pid(), ProcFileV1::Stat)?;
        let stat = parse_proc_stat(&self.stat.current)?;
        let after = original.info()?;
        let identity = identity_from_stat(original, before, stat, after)?;
        self.original_identity = Some(identity);
        Ok(identity)
    }

    /// Captures the same process's context once, following stat capture.
    ///
    /// # Errors
    /// Rejects wrong phase, unavailable/oversized context or changed original
    /// process facts. The bytes are DATA; the purpose owner must match its role.
    pub fn capture_context(&mut self, original: &PidFd) -> Result<&[u8]> {
        let operation = self.begin(ObservationPhaseV1::StatCaptured)?;
        let result = operation.observations.capture_context_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)?;
        Ok(&self.context.current)
    }

    fn capture_context_inner(&mut self, original: &PidFd) -> Result<()> {
        let before = self.require_original_info(original)?;
        self.context.capture(before.pid(), ProcFileV1::Context)?;
        self.require_original_info(original)?;
        Ok(())
    }

    /// Observes fresh identity using the same original stat descriptor.
    ///
    /// # Errors
    /// Rejects uncompleted/closed capture, reread denial, malformed stat,
    /// changed original process facts or exit. No pathname is reopened.
    pub fn observe_identity(&mut self, original: &PidFd) -> Result<PidFdProcessIdentity> {
        let operation = self.begin(ObservationPhaseV1::Ready)?;
        let result = operation.observations.observe_identity_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)
    }

    fn observe_identity_inner(&mut self, original: &PidFd) -> Result<PidFdProcessIdentity> {
        let identity = self.reread_identity_inner(original)?;
        if Some(identity) != self.original_identity {
            return Err(Error::invalid("proc observation", "original process identity changed"));
        }
        Ok(identity)
    }

    // Current-self purpose comparison remains in Core, with its original error.
    pub(super) fn observe_stat_identity(
        &mut self,
        original: &PidFd,
    ) -> Result<PidFdProcessIdentity> {
        let operation = self.begin(ObservationPhaseV1::StatCaptured)?;
        let result = operation.observations.reread_identity_inner(original);
        operation.finish(result, ObservationPhaseV1::StatCaptured)
    }

    fn reread_identity_inner(&mut self, original: &PidFd) -> Result<PidFdProcessIdentity> {
        let before = original.info()?;
        self.stat.read(MAXIMUM_PROC_STAT_BYTES)?;
        let stat = parse_proc_stat(&self.stat.current)?;
        let after = original.info()?;
        identity_from_stat(original, before, stat, after)
    }

    pub(super) fn fence(&mut self) {
        self.phase = ObservationPhaseV1::Closed;
    }

    /// Rereads current context from the same original descriptor.
    ///
    /// # Errors
    /// Rejects uncompleted/closed capture, reread denial, excess bytes,
    /// changed original GET_INFO facts or exit. Role matching remains separate.
    pub fn observe_context(&mut self, original: &PidFd) -> Result<&[u8]> {
        let operation = self.begin(ObservationPhaseV1::Ready)?;
        let result = operation.observations.observe_context_inner(original);
        operation.finish(result, ObservationPhaseV1::Ready)?;
        Ok(&self.context.current)
    }

    fn observe_context_inner(&mut self, original: &PidFd) -> Result<()> {
        self.require_original_info(original)?;
        self.context.read(CONTEXT_BYTES)?;
        self.require_original_info(original)?;
        Ok(())
    }

    fn require_original_info(&self, original: &PidFd) -> Result<PidFdInfo> {
        let observed = original.info()?;
        if Some(observed) != self.original_info || !original.is_alive()? {
            return Err(Error::invalid("proc observation", "original process changed or exited"));
        }
        Ok(observed)
    }

    fn begin(&mut self, expected: ObservationPhaseV1) -> Result<ProcObservationOperationV1<'_>> {
        if self.phase != expected {
            self.phase = ObservationPhaseV1::Closed;
            return Err(closed());
        }
        // Arm BEFORE every syscall; caught unwind/drop/forget cannot reopen it.
        self.phase = ObservationPhaseV1::Closed;
        Ok(ProcObservationOperationV1 { observations: self })
    }
}

struct ProcObservationOperationV1<'observation> {
    observations: &'observation mut PidFdProcObservationsV1,
}

impl ProcObservationOperationV1<'_> {
    fn finish<T>(self, result: Result<T>, next: ObservationPhaseV1) -> Result<T> {
        if result.is_ok() {
            self.observations.phase = next;
        }
        result
    }
}

fn closed() -> Error {
    Error::invalid("proc observation", "original observation is permanently closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty(phase: ObservationPhaseV1) -> PidFdProcObservationsV1 {
        PidFdProcObservationsV1 {
            stat: ProcDescriptorV1::empty(),
            context: ProcDescriptorV1::empty(),
            original_info: None,
            original_identity: None,
            phase,
            nix_helper: None,
        }
    }

    #[test]
    fn stat_only_state_does_not_satisfy_public_ready_gate() {
        let mut observations = empty(ObservationPhaseV1::StatCaptured);
        let operation = observations.begin(ObservationPhaseV1::StatCaptured).unwrap();
        operation
            .finish(Ok(()), ObservationPhaseV1::StatCaptured)
            .unwrap();

        assert_eq!(observations.phase, ObservationPhaseV1::StatCaptured);
        assert!(observations.begin(ObservationPhaseV1::Ready).is_err());
        assert_eq!(observations.phase, ObservationPhaseV1::Closed);
    }

    #[test]
    fn stat_only_outer_fence_is_permanent() {
        let mut observations = empty(ObservationPhaseV1::StatCaptured);
        observations.fence();

        assert_eq!(observations.phase, ObservationPhaseV1::Closed);
        assert!(observations.begin(ObservationPhaseV1::StatCaptured).is_err());
    }

    #[test]
    fn unfinished_and_forgotten_observations_stay_closed() {
        let mut dropped = empty(ObservationPhaseV1::Fresh);
        drop(dropped.begin(ObservationPhaseV1::Fresh).unwrap());
        assert_eq!(dropped.phase, ObservationPhaseV1::Closed);

        let mut forgotten = empty(ObservationPhaseV1::Ready);
        std::mem::forget(forgotten.begin(ObservationPhaseV1::Ready).unwrap());
        assert_eq!(forgotten.phase, ObservationPhaseV1::Closed);
    }

    #[test]
    fn only_same_successful_open_operation_restores_next_phase() {
        let mut observations = empty(ObservationPhaseV1::Fresh);
        observations.begin(ObservationPhaseV1::Fresh).unwrap()
            .finish(Ok(()), ObservationPhaseV1::StatCaptured).unwrap();
        assert_eq!(observations.phase, ObservationPhaseV1::StatCaptured);

        assert!(observations.begin(ObservationPhaseV1::Fresh).is_err());
        assert_eq!(observations.phase, ObservationPhaseV1::Closed);
        assert!(observations.begin(ObservationPhaseV1::StatCaptured).is_err());
    }

    #[test]
    fn original_err_and_caught_unwind_do_not_reopen_observations() {
        let mut failed = empty(ObservationPhaseV1::Ready);
        let result = failed.begin(ObservationPhaseV1::Ready).unwrap()
            .finish::<()>(Err(closed()), ObservationPhaseV1::Ready);
        assert!(result.is_err());
        assert_eq!(failed.phase, ObservationPhaseV1::Closed);

        let mut unwound = empty(ObservationPhaseV1::Fresh);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _operation = unwound.begin(ObservationPhaseV1::Fresh).unwrap();
            panic!("pure observation unwind");
        }));
        assert!(caught.is_err());
        assert_eq!(unwound.phase, ObservationPhaseV1::Closed);
    }
}

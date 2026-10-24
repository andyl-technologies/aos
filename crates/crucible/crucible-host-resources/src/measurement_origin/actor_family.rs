//! Retains the authenticated actor family that bounds host and native workers.
//!
//! The actor's guardian and native workload are siblings below the same paid
//! aggregate. These pins authenticate containment; the existing actor owns the
//! reservation, and no child or thread join refunds the enclosing physical peak.

use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd;
use std::sync::Arc;

use crate::host_services::{HostServiceLease, HostServiceLeasePair};
use crate::host_supervision::HostOperationGuard;

use super::{CertifiedMeasurementMode, CertifiedNativeRoleEvidence, MeasurementOriginError};

const ROOT: &str = "/sys/fs/cgroup/crucible-measurement-actor";
const MEMBERSHIP: &[u8] = b"0::/crucible-measurement-actor/guardian\n";
const MAX_CONTROL_BYTES: usize = 128;

/// Pins one genuinely authenticated actor's enclosing kernel family.
///
/// The original actor must retain this owner through worker and descendant
/// retirement. It exposes no directory, resource account or native grant.
/// A successful check never substitutes for the independent Source purpose.
#[must_use = "retain the same actor family through physical worker and child retirement"]
pub struct AuthenticatedActorFamily {
    parent: File,
    guardian: File,
    workload: File,
    generation: u64,
    kernel_measurement: bool,
    // All descriptor-owning fields close before either financing control.
    _controls: HostServiceLeasePair,
    original: Arc<HostOperationGuard>,
}

impl std::fmt::Debug for AuthenticatedActorFamily {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedActorFamily")
            .finish_non_exhaustive()
    }
}

impl CertifiedNativeRoleEvidence {
    /// Authenticates and retains the same actor's kernel containment family.
    ///
    /// The closed actor publisher supplies its own original preparation and
    /// freshly reserved resident/metadata controls before this method opens any
    /// descriptor. Extent checks here do not certify a foreign allocator as that
    /// publisher: the caller must preserve its existing same-account binding.
    ///
    /// # Errors
    /// Refuses the original first cut, insufficient prepaid controls, absent or
    /// replaced containment, incompatible controls or actor membership, and an
    /// original refusal after successful authentication.
    pub fn retain_actor_family(
        &self,
        original: Arc<HostOperationGuard>,
        resident: HostServiceLease,
        metadata: HostServiceLease,
    ) -> Result<AuthenticatedActorFamily, MeasurementOriginError> {
        check_original(&original)?;
        let extent = AuthenticatedActorFamily::control_extent();
        if self.generation() == 0
            || resident.file_descriptors() < AuthenticatedActorFamily::descriptor_peak()
            || resident.resident_bytes() < extent
            || metadata.resident_bytes() < extent
        {
            return Err(refused("actor family prepaid controls"));
        }

        let controls = HostServiceLeasePair::new(resident, metadata);
        let parent = open_directory(rustix::fs::CWD, ROOT)?;
        let guardian = open_directory(&parent, "guardian")?;
        let workload = open_directory(&parent, "workload")?;
        let owner = AuthenticatedActorFamily {
            parent,
            guardian,
            workload,
            original,
            generation: self.generation(),
            kernel_measurement: matches!(self.mode(), CertifiedMeasurementMode::KernelMeasurement),
            _controls: controls,
        };
        owner.check_host_membership()?;
        Ok(owner)
    }
}

impl AuthenticatedActorFamily {
    /// Returns the exact inline owner extent to prepay in both original counters.
    #[must_use]
    pub const fn control_extent() -> u64 {
        std::mem::size_of::<Self>() as u64
    }

    /// Returns this target's shared owner body and existing Arc header extent.
    ///
    /// # Errors
    /// Refuses target layout or integer overflow before allocation.
    pub fn shared_control_extent() -> Result<u64, MeasurementOriginError> {
        let (layout, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<Self>())
        .map_err(|_| refused("actor family shared control layout"))?;
        u64::try_from(layout.pad_to_align().size())
            .map_err(|_| refused("actor family shared control extent"))
    }

    /// Returns three retained pins plus one temporary verification descriptor.
    #[must_use]
    pub const fn descriptor_peak() -> u64 {
        4
    }

    /// Checks live host membership and unchanged authenticated family controls.
    ///
    /// All reads use bounded stack buffers. Cache and TLS storage remain covered
    /// by the enclosing actor reservation after individual worker leases close.
    ///
    /// # Errors
    /// Preserves an initiating original, directory, control or membership error.
    /// Successful verification receives a final cut on the same original.
    pub fn check_host_membership(&self) -> Result<(), MeasurementOriginError> {
        check_original(&self.original)?;
        let named = open_directory(rustix::fs::CWD, ROOT)?;
        require_same_directory(&self.parent, &named)?;
        drop(named);
        require_child(&self.parent, "guardian", &self.guardian)?;
        require_child(&self.parent, "workload", &self.workload)?;

        for (name, expected) in [
            ("memory.max", b"17179869184\n".as_slice()),
            ("pids.max", b"4096\n".as_slice()),
            ("cpu.max", b"1000000 100000\n".as_slice()),
            ("memory.swap.max", self.swap_limit()),
        ] {
            require_control(&self.parent, name, expected)?;
        }
        require_control(&self.parent, "cgroup.procs", b"")?;
        require_control(&self.guardian, "memory.swap.max", b"0\n")?;
        require_control(&self.workload, "memory.swap.max", self.swap_limit())?;
        require_control(rustix::fs::CWD, "/proc/self/cgroup", MEMBERSHIP)?;
        check_original(&self.original)
    }

    /// Matches an original factory's delegated root to the pinned workload.
    ///
    /// This accepts an already-open directory and returns no path or descriptor.
    /// It must run before the factory starts a watcher or a Source worker.
    ///
    /// # Errors
    /// Refuses changed host containment, a foreign or replaced workload root,
    /// and the same original's final cut after a successful comparison.
    pub fn verify_workload_directory(
        &self,
        directory: impl AsFd,
    ) -> Result<(), MeasurementOriginError> {
        self.check_host_membership()?;
        require_same_directory(&self.workload, directory)?;
        check_original(&self.original)
    }

    /// Matches the existing actor generation without issuing a new purpose.
    #[must_use]
    pub fn matches_generation(&self, generation: u64) -> bool {
        self.generation == generation
    }

    fn swap_limit(&self) -> &'static [u8] {
        if self.kernel_measurement {
            b"4294967296\n"
        } else {
            b"0\n"
        }
    }
}

fn check_original(original: &HostOperationGuard) -> Result<(), MeasurementOriginError> {
    original
        .wait_slice()
        .map(|_| ())
        .map_err(MeasurementOriginError::OriginalOperation)
}

fn refused(site: &'static str) -> MeasurementOriginError {
    MeasurementOriginError::Authentication(site)
}

fn open_directory(directory: impl AsFd, name: &str) -> Result<File, MeasurementOriginError> {
    let descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(descriptor);
    if rustix::fs::fstatfs(&file)?.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(refused("actor family cgroup filesystem"));
    }
    Ok(file)
}

fn require_same_directory(
    expected: impl AsFd,
    actual: impl AsFd,
) -> Result<(), MeasurementOriginError> {
    let expected = rustix::fs::fstat(expected)?;
    let actual = rustix::fs::fstat(actual)?;
    if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
        return Err(refused("actor family directory identity"));
    }
    Ok(())
}

fn require_child(parent: &File, name: &str, expected: &File) -> Result<(), MeasurementOriginError> {
    let actual = open_directory(parent, name)?;
    require_same_directory(expected, &actual)
}

fn require_control(
    directory: impl AsFd,
    name: &str,
    expected: &[u8],
) -> Result<(), MeasurementOriginError> {
    let descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?;
    let mut file = File::from(descriptor);
    let mut bytes = [0; MAX_CONTROL_BYTES];
    let mut used = 0;
    loop {
        if used == bytes.len() {
            return Err(refused("actor family control extent"));
        }
        let count = file.read(&mut bytes[used..])?;
        if count == 0 {
            break;
        }
        used += count;
    }
    if bytes[..used] != *expected {
        return Err(refused("actor family control or membership"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

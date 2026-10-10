//! Retains one admitted writable device-digest mapping until joined cleanup.
//!
//! This private GPL owner accepts only the matching native broker's compulsory
//! attestation of an already admitted purpose. Descriptor metadata and setup
//! generations identify that purpose; they cannot issue it. The worker borrows
//! the mapping, while its parent control retains the actual allocation.

// SPDX-License-Identifier: GPL-2.0-only

use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::ptr::NonNull;

use crucible_protocol::{DEVICE_DIGEST_WORKSPACE_BYTES, DeviceDigestWorkspaceBinding};

/// Exact private native attestation; no amount or returned allowance is present.
type NativeWorkspaceClaim = extern "C" fn(u64, u64, u64, u64, u64, u64, u64, i32, i32) -> i32;

/// Fixed failures that require no diagnostic allocation after refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeviceDigestWorkspaceError {
    /// The same installing Source refused before workspace birth.
    #[error("original startup Source refused: {source}")]
    StartupSource {
        /// Exact fixed native refusal retained by the original Source owner.
        source: crate::StartupSourceError,
    },
    /// The running native implementation lacks the compulsory attestation.
    #[error("the required device workspace admission export is absent")]
    MissingAdmission,
    /// The concrete installing native owner refused the fixed purpose.
    #[error("native device workspace admission refused ({status})")]
    Admission {
        /// Unmodified status from the matched native attestation.
        status: i32,
    },
    /// Actual descriptor geometry or identity disagrees with the handover.
    #[error("device workspace descriptor is invalid: {reason}")]
    Descriptor {
        /// Fixed validation rule that refused the handover.
        reason: &'static str,
    },
    /// An actual mapping, inspection or close operation failed.
    #[error("device workspace {operation} failed ({errno})")]
    System {
        /// Actual effect or inspection that failed.
        operation: &'static str,
        /// Unmodified kernel errno.
        errno: i32,
    },
    /// An incarnation or retained-owner invariant failed.
    #[error("device workspace ownership is invalid: {reason}")]
    Ownership {
        /// Fixed incarnation or custody rule that refused the operation.
        reason: &'static str,
    },
}

/// A refused claim retains the exact descriptor even if native acceptance was uncertain.
///
/// The caller moves this inline owner into its already retained setup/runtime
/// holder. A nonzero status cannot prove that a native borrower never accepted.
pub(crate) struct DeviceDigestWorkspacePreparationFailure {
    pub(crate) workspace: DeviceDigestWorkspace,
    pub(crate) source: DeviceDigestWorkspaceError,
}

/// Holds both initial claim descriptors while native acceptance is uncertain.
pub(crate) struct RefusedInitialDeviceDigestWorkspace {
    workspace: Option<DeviceDigestWorkspace>,
    purpose_plan: Option<OwnedFd>,
}

impl RefusedInitialDeviceDigestWorkspace {
    pub(crate) fn retain_with_source_owner(
        failure: DeviceDigestWorkspacePreparationFailure,
    ) -> Self {
        Self {
            workspace: Some(failure.workspace),
            purpose_plan: None,
        }
    }

    pub(crate) fn retain(
        failure: DeviceDigestWorkspacePreparationFailure,
        purpose_plan: OwnedFd,
    ) -> Self {
        Self {
            workspace: Some(failure.workspace),
            purpose_plan: Some(purpose_plan),
        }
    }
}

impl Drop for RefusedInitialDeviceDigestWorkspace {
    fn drop(&mut self) {
        // Neither claim descriptor can be proved unborrowed on a nonzero
        // status. Their same native purpose remains outstanding until actual
        // process containment; dropping this header does not report cleanup.
        if let Some(plan) = self.purpose_plan.take() {
            let _retained_until_exit = plan.into_raw_fd();
        }
        drop(self.workspace.take());
    }
}

/// A failed close retains the same mapping/descriptor rather than a replacement.
pub(crate) struct DeviceDigestWorkspaceCloseFailure {
    pub(crate) workspace: DeviceDigestWorkspace,
    pub(crate) source: DeviceDigestWorkspaceError,
}

/// Private mapping owner; only a joined parent may close a running worker's view.
pub(crate) struct DeviceDigestWorkspace {
    descriptor: Option<OwnedFd>,
    mapping: Option<*mut libc::c_void>,
    owner_process: u32,
    binding: DeviceDigestWorkspaceBinding,
    terminal_failure: Option<DeviceDigestWorkspaceError>,
}

// SAFETY: this owner is moved only into the private parent-held Mutex. A worker
// obtains a mutable view through that lock; no pointer, Clone or shared writable
// view escapes. The mapping remains alive until explicit joined cleanup.
unsafe impl Send for DeviceDigestWorkspace {}

impl DeviceDigestWorkspace {
    /// Attests the compulsory original purpose before any worker control birth.
    ///
    /// The native export must validate the actual installing plugin, original
    /// slot and retained resource. Missing/unmatched native source refuses; an
    /// fd, generation or budget scalar never substitutes for that attestation.
    pub(crate) fn prepare(
        plugin_id: u64,
        process_generation: u64,
        binding: DeviceDigestWorkspaceBinding,
        descriptor: OwnedFd,
        purpose_plan_fd: i32,
    ) -> Result<Self, DeviceDigestWorkspacePreparationFailure> {
        let mut workspace = Self {
            descriptor: Some(descriptor),
            mapping: None,
            owner_process: std::process::id(),
            binding,
            terminal_failure: None,
        };
        let claim = (|| {
            let descriptor =
                workspace
                    .descriptor
                    .as_ref()
                    .ok_or(DeviceDigestWorkspaceError::Ownership {
                        reason: "preparation descriptor is absent",
                    })?;
            validate_descriptor(descriptor, binding)?;
            let claim = resolve_native_claim()?;
            let status = claim(
                plugin_id,
                process_generation,
                binding.account_generation,
                binding.workspace_generation,
                binding.device,
                binding.inode,
                DEVICE_DIGEST_WORKSPACE_BYTES,
                descriptor.as_raw_fd(),
                purpose_plan_fd,
            );
            if status != 0 {
                return Err(DeviceDigestWorkspaceError::Admission { status });
            }
            Ok(())
        })();
        if let Err(source) = claim {
            // No later retry can clear this uncertainty. The existing holder
            // keeps the actual owner through matching native containment.
            workspace.terminal_failure = Some(source);
            return Err(DeviceDigestWorkspacePreparationFailure { workspace, source });
        }
        Ok(workspace)
    }

    /// Installs the mapping inside its already retained worker control.
    ///
    /// Every refusal leaves this same owner in place. In particular, a failed
    /// fork disposition never discards the mapping or its independent cleanup.
    pub(crate) fn map(&mut self) -> Result<(), DeviceDigestWorkspaceError> {
        if self.owner_process != std::process::id()
            || self.mapping.is_some()
            || self.terminal_failure.is_some()
        {
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "mapping installation is repeated or belongs to another incarnation",
            });
        }
        let descriptor = self
            .descriptor
            .as_ref()
            .ok_or(DeviceDigestWorkspaceError::Ownership {
                reason: "descriptor is absent",
            })?;

        // SAFETY: the descriptor has fixed sealed sizing and writable access;
        // its actual original purpose was attested before this mapping effect.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                DEVICE_DIGEST_WORKSPACE_BYTES as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                descriptor.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(system_error("map"));
        }
        self.mapping = Some(address);
        if address.is_null() {
            // Retain even an unusable mapping until explicit fallible cleanup.
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "mapping address is null",
            });
        }

        // SAFETY: the mapping is live and exactly the declared fixed extent.
        if unsafe {
            libc::madvise(
                address,
                DEVICE_DIGEST_WORKSPACE_BYTES as usize,
                libc::MADV_DONTFORK,
            )
        } != 0
        {
            return Err(system_error("exclude from fork"));
        }
        Ok(())
    }

    /// Borrows exactly the admitted extent without constructing an array value.
    pub(crate) fn bytes(&mut self) -> Result<&mut [u8; 65_536], DeviceDigestWorkspaceError> {
        if self.owner_process != std::process::id() || self.terminal_failure.is_some() {
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "mapping belongs to another incarnation or is unsettled",
            });
        }
        let mapping = self
            .mapping
            .and_then(|address| NonNull::new(address.cast::<u8>()))
            .ok_or(DeviceDigestWorkspaceError::Ownership {
                reason: "mapping is absent or null",
            })?;
        // SAFETY: this mutable owner supplies exclusive access to its live,
        // fixed writable mapping, whose length cannot change under its seals.
        Ok(unsafe { &mut *mapping.as_ptr().cast::<[u8; 65_536]>() })
    }

    /// Reports only the private alias number for matching native status.
    pub(crate) fn descriptor_number(&self) -> Result<i32, DeviceDigestWorkspaceError> {
        if self.binding.account_generation == 0 || self.binding.workspace_generation == 0 {
            return Err(DeviceDigestWorkspaceError::Ownership {
                reason: "retained original workspace identity is absent",
            });
        }
        self.descriptor.as_ref().map(AsRawFd::as_raw_fd).ok_or(
            DeviceDigestWorkspaceError::Ownership {
                reason: "claimed descriptor is absent",
            },
        )
    }

    /// Disarms a copied absent mapping before any child address/number reuse.
    ///
    /// This runs at authenticated early child entry on the directly held fork
    /// owner, not by locking a vanished worker's shared control. This owner is
    /// the sole closer of its descriptor; native pruning closes other aliases.
    pub(crate) fn disarm_inherited(mut self) -> Result<(), DeviceDigestWorkspaceCloseFailure> {
        if let Some(source) = self.terminal_failure {
            return Err(DeviceDigestWorkspaceCloseFailure {
                workspace: self,
                source,
            });
        }
        if self.owner_process == std::process::id() {
            return Err(DeviceDigestWorkspaceCloseFailure {
                workspace: self,
                source: DeviceDigestWorkspaceError::Ownership {
                    reason: "child disarm requested in the owning parent",
                },
            });
        }
        self.mapping.take();
        self.close_descriptor()
    }

    /// Unmaps and closes only after the real worker joined and aliases closed.
    pub(crate) fn try_close(mut self) -> Result<(), DeviceDigestWorkspaceCloseFailure> {
        if let Some(source) = self.terminal_failure {
            return Err(DeviceDigestWorkspaceCloseFailure {
                workspace: self,
                source,
            });
        }
        if self.owner_process != std::process::id() {
            return Err(DeviceDigestWorkspaceCloseFailure {
                workspace: self,
                source: DeviceDigestWorkspaceError::Ownership {
                    reason: "inherited absent mapping requires early disarm",
                },
            });
        }
        if let Some(mapping) = self.mapping {
            // SAFETY: this unique joined owner still owns the exact live view.
            if unsafe { libc::munmap(mapping, DEVICE_DIGEST_WORKSPACE_BYTES as usize) } != 0 {
                let source = system_error("unmap");
                self.terminal_failure = Some(source);
                return Err(DeviceDigestWorkspaceCloseFailure {
                    workspace: self,
                    source,
                });
            }
            self.mapping.take();
        }
        self.close_descriptor()
    }

    fn close_descriptor(mut self) -> Result<(), DeviceDigestWorkspaceCloseFailure> {
        if let Some(descriptor) = self.descriptor.take() {
            let raw = descriptor.into_raw_fd();
            // SAFETY: this owner relinquished its sole descriptor exactly once.
            // A failed Linux close is never retried by number or stale Drop.
            if unsafe { libc::close(raw) } != 0 {
                let source = system_error("close descriptor");
                self.terminal_failure = Some(source);
                return Err(DeviceDigestWorkspaceCloseFailure {
                    workspace: self,
                    source,
                });
            }
        }
        Ok(())
    }
}

impl Drop for DeviceDigestWorkspace {
    fn drop(&mut self) {
        // Unexpected disposal cannot assert successful close or let an absent
        // fork copy unmap a reused address. Running/unsettled owners are retained
        // by the parent control; lost ownership is confined to native physical
        // termination, while the external original purpose remains outstanding.
        if let Some(descriptor) = self.descriptor.take() {
            let _retained_until_containment = descriptor.into_raw_fd();
        }
        self.mapping.take();
    }
}

fn validate_descriptor(
    descriptor: &OwnedFd,
    binding: DeviceDigestWorkspaceBinding,
) -> Result<(), DeviceDigestWorkspaceError> {
    let fd = descriptor.as_raw_fd();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat initializes this output on success and retains no pointer.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(system_error("inspect descriptor"));
    }
    // SAFETY: successful fstat initialized the entire structure.
    let stat = unsafe { stat.assume_init() };
    // SAFETY: these descriptor queries neither consume nor retain the fd.
    let (access, flags, seals, offset) = unsafe {
        (
            libc::fcntl(fd, libc::F_GETFL),
            libc::fcntl(fd, libc::F_GETFD),
            libc::fcntl(fd, libc::F_GET_SEALS),
            libc::lseek(fd, 0, libc::SEEK_CUR),
        )
    };
    let required_seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_size != DEVICE_DIGEST_WORKSPACE_BYTES as libc::off_t
        || stat.st_dev != binding.device
        || stat.st_ino != binding.inode
        || binding.account_generation == 0
        || binding.workspace_generation == 0
        || access < 0
        || access & libc::O_ACCMODE != libc::O_RDWR
        || flags < 0
        || flags & libc::FD_CLOEXEC == 0
        || seals != required_seals
        || offset != 0
    {
        return Err(DeviceDigestWorkspaceError::Descriptor {
            reason: "extent, identity, access, offset, generations or seals differ",
        });
    }
    Ok(())
}

fn resolve_native_claim() -> Result<NativeWorkspaceClaim, DeviceDigestWorkspaceError> {
    // SAFETY: the literal is NUL-terminated and selects only the matching GPL
    // native runtime. The actual export must authenticate the closed purpose;
    // resolving its address never supplies funding or returns an allowance.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"qemu_plugin_crucible_device_digest_workspace_claim_v1".as_ptr(),
        )
    };
    if symbol.is_null() {
        return Err(DeviceDigestWorkspaceError::MissingAdmission);
    }
    // SAFETY: the matched native declaration uses this exact scalar signature.
    Ok(unsafe { std::mem::transmute::<*mut libc::c_void, NativeWorkspaceClaim>(symbol) })
}

fn system_error(operation: &'static str) -> DeviceDigestWorkspaceError {
    DeviceDigestWorkspaceError::System {
        operation,
        errno: std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    }
}

#[cfg(test)]
impl DeviceDigestWorkspace {
    // A local descriptor/mapping fixture supplies no deployed native claim.
    pub(crate) fn test_owner() -> Self {
        use std::os::fd::FromRawFd;

        // SAFETY: the literal is NUL-terminated; the returned fd is unique.
        let descriptor = unsafe {
            libc::memfd_create(
                c"device-workspace-control-test".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(descriptor >= 0);
        // SAFETY: memfd_create returned this unique owned descriptor.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        assert_eq!(
            // SAFETY: the live unique descriptor permits sizing this local fixture; no mapping exists.
            unsafe { libc::ftruncate(descriptor.as_raw_fd(), 65_536) },
            0
        );
        let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
        assert_eq!(
            // SAFETY: the live memfd and supported seal bitmask require no pointer argument.
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_ADD_SEALS, seals) },
            0
        );
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(
            // SAFETY: the live descriptor and writable stat storage remain valid for the call.
            unsafe { libc::fstat(descriptor.as_raw_fd(), stat.as_mut_ptr()) },
            0
        );
        // SAFETY: successful fstat initialized the complete metadata.
        let stat = unsafe { stat.assume_init() };
        let binding = DeviceDigestWorkspaceBinding {
            account_generation: 1,
            workspace_generation: 1,
            device: stat.st_dev,
            inode: stat.st_ino,
        };
        validate_descriptor(&descriptor, binding).unwrap();
        Self {
            descriptor: Some(descriptor),
            mapping: None,
            owner_process: std::process::id(),
            binding,
            terminal_failure: None,
        }
    }
}

//! Keeps digest-worker ownership separate from Source's physical mapping.
//!
//! Production mapping creation and canonical custody live in the pinned Runtime.
//! The physical SDK lends no mutable workspace or worker Original, so this
//! worker-facing type has no production constructor yet. Its existing mapping
//! and terminal methods retain their worker behavior. Only explicit lifecycle
//! fixtures currently construct this holder; operating cutover remains deferred.

// SPDX-License-Identifier: GPL-2.0-only

use std::os::fd::AsRawFd;
use std::os::fd::IntoRawFd;
#[cfg(test)]
use std::os::fd::OwnedFd;
use std::ptr::NonNull;

use crucible_qemu_protocol::DEVICE_DIGEST_WORKSPACE_BYTES;
use crucible_qemu_protocol::DeviceDigestWorkspaceBinding;

/// Fixed failures that require no diagnostic allocation after refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeviceDigestWorkspaceError {
    /// The same installing Source refused before workspace birth.
    #[error("original startup Source refused: {source}")]
    StartupSource {
        /// Exact fixed native refusal retained by the original Source owner.
        source: crate::StartupSourceError,
    },
    /// The genuine Source mapping method returned this signed status.
    #[error("Source workspace mapping refused ({status})")]
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

/// A local fixture refuses while retaining its exact descriptor.
#[cfg(test)]
pub(crate) struct DeviceDigestWorkspacePreparationFailure {
    pub(crate) workspace: DeviceDigestWorkspace,
    pub(crate) source: DeviceDigestWorkspaceError,
}

/// A failed close retains the same mapping/descriptor rather than a replacement.
pub(crate) struct DeviceDigestWorkspaceCloseFailure {
    pub(crate) workspace: DeviceDigestWorkspace,
    pub(crate) source: DeviceDigestWorkspaceError,
}

/// Worker-facing holder; production awaits a genuine exclusive Source lease.
pub(crate) struct DeviceDigestWorkspace {
    descriptor: Option<crate::startup_source::SetupDescriptor>,
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
    /// Constructs only the explicit local worker fixture, without a native claim.
    #[cfg(test)]
    pub(crate) fn prepare_fixture(
        binding: DeviceDigestWorkspaceBinding,
        descriptor: crate::startup_source::SetupDescriptor,
    ) -> Result<Self, DeviceDigestWorkspacePreparationFailure> {
        let workspace = Self {
            descriptor: Some(descriptor),
            mapping: None,
            owner_process: std::process::id(),
            binding,
            terminal_failure: None,
        };
        let validation = workspace
            .descriptor
            .as_ref()
            .ok_or(DeviceDigestWorkspaceError::Ownership {
                reason: "local fixture descriptor is absent",
            })
            .and_then(|descriptor| validate_descriptor(descriptor, binding));
        match validation {
            Ok(()) => Ok(workspace),
            Err(source) => Err(DeviceDigestWorkspacePreparationFailure { workspace, source }),
        }
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

        // SAFETY: this local fixture validated fixed sealed sizing and writable
        // access. It claims no deployed Source role or operating Original.
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
            let Some(descriptor) = descriptor.into_owned() else {
                // Native keeps its role until physical process retirement.
                return Ok(());
            };
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
            descriptor.retain_until_process_exit();
        }
        self.mapping.take();
    }
}

#[cfg(test)]
fn validate_descriptor(
    descriptor: &crate::startup_source::SetupDescriptor,
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
    // A local descriptor/mapping fixture supplies no deployed Source owner.
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
        let descriptor = crate::startup_source::SetupDescriptor::from(descriptor);
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

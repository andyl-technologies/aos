//! Fixed descriptor binding for the device SHA-256 worker workspace.
//!
//! The binding identifies an already admitted resource; it does not grant an
//! account, allocation, worker birth, or descriptor-import permission. Setup
//! schema one derives the fixed extent instead of accepting a caller size.
//!
//! ```text
//! Setup payload, all integers big endian (56 bytes):
//! region_len:u64, workspace_schema:u32, workspace_flags:u32,
//! process_generation:u64, account_generation:u64, workspace_generation:u64,
//! workspace_device:u64, workspace_inode:u64
//! ```

/// Exact writable backing extent used by every device digest worker.
pub const DEVICE_DIGEST_WORKSPACE_BYTES: u64 = 65_536;

/// Actual backing and original-slot identities carried by setup.
///
/// These observational fields must be authenticated against the closed launch
/// owner and native broker before any allocation or worker birth. Their values
/// alone are not funding or authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceDigestWorkspaceBinding {
    /// Actual retained native-account slot generation.
    pub account_generation: u64,
    /// Once-issued resource generation for this native incarnation.
    pub workspace_generation: u64,
    /// Actual device number reported by the workspace descriptor.
    pub device: u64,
    /// Actual inode number reported by the workspace descriptor.
    pub inode: u64,
}

/// Outbound workspace descriptor and its fixed observational binding.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupDeviceDigestWorkspaceFd {
    /// Borrowed descriptor retained by the original resource owner.
    pub fd: std::os::fd::RawFd,
    /// Binding derived from that same original owner's resource.
    pub binding: DeviceDigestWorkspaceBinding,
}

impl DeviceDigestWorkspaceBinding {
    pub(crate) fn validate(&self) -> Result<(), crate::FrameDecodeError> {
        if self.account_generation == 0 || self.workspace_generation == 0 {
            return Err(crate::FrameDecodeError::InvalidSetupWorkspace {
                reason: "workspace account and resource generations must be nonzero",
            });
        }
        Ok(())
    }
}

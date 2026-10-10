//! Retains one issued device-digest workspace through actual child containment.
//!
//! The native account supplies an opaque, source-qualified purpose before any
//! allocation or descriptor effect. The external holder owns that purpose;
//! shared setup views borrow one prepaid body without issuing another account.

use std::alloc::Layout;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use crucible_protocol::plugin_setup_plan::DeviceDigestPurpose;
use crucible_protocol::{DEVICE_DIGEST_WORKSPACE_BYTES, SetupDeviceDigestWorkspaceFd};
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, fstat, ftruncate, memfd_create};

use crate::OriginalActorAccountError;
use crate::linux_attempt_host::OriginalDeviceDigestWorkspacePurpose;

/// Fixed workspace effects preserve their actual account or kernel cause.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DeviceDigestWorkspaceIssueError {
    #[error("the issued device workspace is unavailable")]
    Unavailable,
    #[error("device workspace {operation} refused: {source}")]
    Kernel {
        operation: &'static str,
        #[source]
        source: rustix::io::Errno,
    },
    #[error("device workspace account refused: {0}")]
    Account(#[source] OriginalActorAccountError),
    #[error("device workspace geometry or backing identity differs")]
    Geometry,
    #[error("a setup view still retains the device workspace")]
    Aliased,
}

/// Shared descriptor body, allocated once before workspace birth.
#[derive(Debug)]
pub(crate) struct DeviceDigestWorkspaceBody {
    descriptor: Option<OwnedFd>,
    record: Option<DeviceDigestPurpose>,
}

impl DeviceDigestWorkspaceBody {
    pub(crate) fn descriptor(
        &self,
    ) -> Result<SetupDeviceDigestWorkspaceFd, DeviceDigestWorkspaceIssueError> {
        let descriptor = self
            .descriptor
            .as_ref()
            .ok_or(DeviceDigestWorkspaceIssueError::Unavailable)?;
        let fields = self.record()?.fields();
        Ok(SetupDeviceDigestWorkspaceFd {
            fd: descriptor.as_raw_fd(),
            binding: crucible_protocol::DeviceDigestWorkspaceBinding {
                account_generation: fields.account_generation,
                workspace_generation: fields.workspace_generation,
                device: fields.device,
                inode: fields.inode,
            },
        })
    }

    pub(crate) fn record(&self) -> Result<&DeviceDigestPurpose, DeviceDigestWorkspaceIssueError> {
        self.record
            .as_ref()
            .ok_or(DeviceDigestWorkspaceIssueError::Unavailable)
    }
}

/// Owns the external purpose until every body alias is physically freed.
#[derive(Debug)]
pub(crate) struct OriginalDeviceDigestWorkspace {
    body: Option<Arc<DeviceDigestWorkspaceBody>>,
    // This keeper is external to the Arc: its census cannot close while the
    // allocator is still freeing the body that the purpose pays for.
    purpose: Option<OriginalDeviceDigestWorkspacePurpose>,
    handed_over: bool,
}

impl OriginalDeviceDigestWorkspace {
    /// Pure target geometry for the fixed issuer; no caller selects an amount.
    pub(crate) fn host_allocation_extent() -> Result<u64, DeviceDigestWorkspaceIssueError> {
        let (arc, _) = Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(Layout::new::<DeviceDigestWorkspaceBody>())
        .map_err(|_| DeviceDigestWorkspaceIssueError::Geometry)?;
        // The enclosing startup and launch-failure controls already pay for
        // their inline holder fields. Only this separate Arc body is added.
        u64::try_from(arc.pad_to_align().size())
            .map_err(|_| DeviceDigestWorkspaceIssueError::Geometry)
    }

    pub(crate) const fn new(purpose: OriginalDeviceDigestWorkspacePurpose) -> Self {
        Self {
            body: None,
            purpose: Some(purpose),
            handed_over: false,
        }
    }

    /// Creates only the already issued fixed backing, without a host mapping.
    ///
    /// The caller places this holder in its prepaid failure storage first, so
    /// every refusal and unwind retains the same descriptor and purpose.
    pub(crate) fn create(&mut self) -> Result<(), DeviceDigestWorkspaceIssueError> {
        if self.body.is_some() || self.handed_over {
            return Err(DeviceDigestWorkspaceIssueError::Unavailable);
        }
        let purpose = self
            .purpose
            .as_mut()
            .ok_or(DeviceDigestWorkspaceIssueError::Unavailable)?;
        purpose
            .check_original()
            .map_err(DeviceDigestWorkspaceIssueError::Account)?;
        purpose
            .enter_workspace_birth()
            .map_err(DeviceDigestWorkspaceIssueError::Account)?;
        self.body = Some(Arc::new(DeviceDigestWorkspaceBody {
            descriptor: None,
            record: None,
        }));
        let body = self
            .body
            .as_mut()
            .and_then(Arc::get_mut)
            .ok_or(DeviceDigestWorkspaceIssueError::Aliased)?;
        body.descriptor = Some(
            memfd_create(
                c"crucible-device-digest",
                MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
            )
            .map_err(|source| kernel("create", source))?,
        );
        let descriptor = body
            .descriptor
            .as_ref()
            .ok_or(DeviceDigestWorkspaceIssueError::Unavailable)?;
        purpose
            .check_original()
            .map_err(DeviceDigestWorkspaceIssueError::Account)?;
        ftruncate(descriptor, DEVICE_DIGEST_WORKSPACE_BYTES)
            .map_err(|source| kernel("size", source))?;
        purpose
            .check_original()
            .map_err(DeviceDigestWorkspaceIssueError::Account)?;
        fcntl_add_seals(
            descriptor,
            SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
        )
        .map_err(|source| kernel("seal", source))?;
        let observed = fstat(descriptor).map_err(|source| kernel("inspect", source))?;
        if observed.st_size != DEVICE_DIGEST_WORKSPACE_BYTES as i64 || observed.st_ino == 0 {
            return Err(DeviceDigestWorkspaceIssueError::Geometry);
        }
        body.record = Some(
            purpose
                .record_for_descriptor(observed.st_dev, observed.st_ino)
                .map_err(DeviceDigestWorkspaceIssueError::Account)?,
        );
        purpose
            .check_original()
            .map_err(DeviceDigestWorkspaceIssueError::Account)
    }

    pub(crate) fn setup_view(
        &self,
    ) -> Result<Arc<DeviceDigestWorkspaceBody>, DeviceDigestWorkspaceIssueError> {
        self.purpose
            .as_ref()
            .ok_or(DeviceDigestWorkspaceIssueError::Unavailable)?
            .check_original()
            .map_err(DeviceDigestWorkspaceIssueError::Account)?;
        let body = self
            .body
            .as_ref()
            .ok_or(DeviceDigestWorkspaceIssueError::Unavailable)?;
        body.descriptor()?;
        Ok(Arc::clone(body))
    }

    /// Marks possible child exposure before its first process effect.
    pub(crate) fn begin_handover(&mut self) -> Result<(), DeviceDigestWorkspaceIssueError> {
        if self.handed_over {
            return Err(DeviceDigestWorkspaceIssueError::Unavailable);
        }
        self.purpose
            .as_ref()
            .ok_or(DeviceDigestWorkspaceIssueError::Unavailable)?
            .check_original()
            .map_err(DeviceDigestWorkspaceIssueError::Account)?;
        self.handed_over = true;
        Ok(())
    }

    /// Frees the body before closing its census after actual process containment.
    pub(crate) fn retire_after_reap(&mut self) -> Result<(), DeviceDigestWorkspaceIssueError> {
        self.retire_body()
    }

    fn retire_body(&mut self) -> Result<(), DeviceDigestWorkspaceIssueError> {
        if self
            .body
            .as_mut()
            .is_some_and(|body| Arc::get_mut(body).is_none())
        {
            return Err(DeviceDigestWorkspaceIssueError::Aliased);
        }
        drop(self.body.take());
        if let Some(purpose) = self.purpose.as_mut() {
            purpose
                .retire_after_body_free()
                .map_err(DeviceDigestWorkspaceIssueError::Account)?;
        }
        drop(self.purpose.take());
        Ok(())
    }
}

impl Drop for OriginalDeviceDigestWorkspace {
    fn drop(&mut self) {
        if !self.handed_over && self.retire_body().is_ok() {
            return;
        }
        // Neither an ambiguous handover nor a surviving view proves native
        // closure. Containment retains the already existing objects, without
        // a replacement allocation or another account.
        if let Some(body) = self.body.take() {
            std::mem::forget(body);
        }
        if let Some(purpose) = self.purpose.take() {
            std::mem::forget(purpose);
        }
    }
}

fn kernel(operation: &'static str, source: rustix::io::Errno) -> DeviceDigestWorkspaceIssueError {
    DeviceDigestWorkspaceIssueError::Kernel { operation, source }
}

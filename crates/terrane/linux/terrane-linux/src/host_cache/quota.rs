//! Queries kernel project-quota assignments without granting provisioning power.
//!
//! Quota limits and project ownership are provisioned by the host administrator.
//! Project-quota queries themselves require host privilege. This raw helper is
//! for a host-supplied supervisor; it is not an unprivileged cache acceptance
//! mechanism. Terrane roles never acquire `CAP_SYS_ADMIN`.

use std::{
    io,
    os::fd::{AsFd, AsRawFd},
};

const GET_PROJECT: libc::c_ulong = 0x801c_581f;
const PROJECT_QUOTA: libc::c_int = 2;

#[repr(C)]
#[derive(Default)]
struct ExtendedAttributes {
    flags: u32,
    extent_size: u32,
    extent_count: u32,
    project: u32,
    cow_extent_size: u32,
    padding: [u8; 8],
}

/// Reports an inode's actual provisioned project quota and current usage.
#[derive(Clone, Debug)]
pub struct ProjectQuota {
    /// Project identifier read from the retained inode.
    pub project: u32,
    /// Kernel-enforced hard allocation ceiling in bytes, absent when unlimited.
    pub hard_limit: Option<u64>,
    /// Kernel-accounted physical space in bytes for the project.
    pub used_bytes: u64,
}

impl ProjectQuota {
    /// Queries the retained inode's project and its filesystem quota record.
    ///
    /// # Errors
    /// Propagates unsupported/inactive quotas, denied queries, kernel failures,
    /// and hard-limit conversion overflow. Such failures do not mean unlimited.
    pub fn inspect(file: impl AsFd) -> io::Result<Self> {
        let descriptor = file.as_fd();
        let mut attributes = ExtendedAttributes::default();
        // SAFETY: GET_PROJECT writes exactly the initialized C-layout structure.
        // The borrowed descriptor remains valid throughout this synchronous call.
        let result = unsafe { libc::ioctl(descriptor.as_raw_fd(), GET_PROJECT, &mut attributes) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut quota = libc::dqblk {
            dqb_bhardlimit: 0,
            dqb_bsoftlimit: 0,
            dqb_curspace: 0,
            dqb_ihardlimit: 0,
            dqb_isoftlimit: 0,
            dqb_curinodes: 0,
            dqb_btime: 0,
            dqb_itime: 0,
            dqb_valid: 0,
        };
        let command = (libc::Q_GETQUOTA << 8) | PROJECT_QUOTA;
        // SAFETY: quotactl_fd receives a live descriptor, scalar command/project,
        // and a valid initialized dqblk output pointer. No pointer escapes.
        let result = unsafe {
            libc::syscall(
                libc::SYS_quotactl_fd,
                descriptor.as_raw_fd(),
                command,
                attributes.project,
                &mut quota as *mut libc::dqblk,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if quota.dqb_valid & (libc::QIF_BLIMITS | libc::QIF_SPACE)
            != (libc::QIF_BLIMITS | libc::QIF_SPACE)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel did not return project limits and usage",
            ));
        }
        let hard_limit = if quota.dqb_bhardlimit == 0 {
            None
        } else {
            Some(quota.dqb_bhardlimit.checked_mul(1024).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "project hard limit overflows bytes",
                )
            })?)
        };
        Ok(Self {
            project: attributes.project,
            hard_limit,
            used_bytes: quota.dqb_curspace,
        })
    }

    /// Verifies an externally provisioned project and exact requested ceiling.
    ///
    /// # Errors
    /// Refuses mismatched projects, absent limits or a weaker hard ceiling.
    pub fn require(&self, project: u32, bytes: u64) -> io::Result<()> {
        if self.project != project || self.hard_limit != Some(bytes) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "required project quota is not provisioned exactly",
            ));
        }
        Ok(())
    }
}

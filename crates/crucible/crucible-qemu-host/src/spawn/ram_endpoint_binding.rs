//! Corroborates the real paid RAM socketpair at its pre-exec sealing boundary.
//!
//! Only the private child-resource owner can create this borrower. Its socket
//! identity and session describe the same retained pair, original purpose and
//! registered target; copied cookies, descriptor numbers and wire bytes create
//! no resource allowance. The borrower allocates and duplicates no descriptor.

use std::os::fd::{AsFd, BorrowedFd};

use crucible_host_resources::host_services::HostServiceLease;
use crucible_host_resources::host_supervision::HostOperationSupervisor;
use rustix::fs::{FileType, fstat};
use rustix::net::sockopt::{socket_cookie, socket_domain, socket_type};
use rustix::net::{AddressFamily, SocketType};

use super::preexec_setup::BorrowedPreexecSetup;
use super::{
    QemuChildProcessContract, QemuSpawnChildResources, QemuSpawnError, QemuSpawnHostResources,
};
use crate::linux_attempt_host::{InstalledProcessPurposeError, OriginalNativeNodeBinding};
use crate::ram_control::RamControlRegistration;

/// Sizes the fixed endpoint suffix in the current sealed process purpose.
pub(crate) const RAM_ENDPOINT_CORROBORATION_BYTES: usize = 176;

/// Borrows the actual child endpoint, paid pair and installed launch lineage.
pub(crate) struct IssuedRamControlEndpoint<'a> {
    child: BorrowedFd<'a>,
    host: BorrowedFd<'a>,
    identity: [u64; 3],
    launch: crate::QemuRamControlLaunch,
    binding: &'a OriginalNativeNodeBinding,
    registration: &'a RamControlRegistration,
    supervisor: &'a HostOperationSupervisor,
    _pair_lease: &'a HostServiceLease,
}

impl QemuSpawnChildResources {
    /// Binds only this owner's real paid pair to the same admitted launch.
    ///
    /// # Errors
    /// Refuses lost original custody, foreign launch identities, absent physical
    /// payment or a changed, invalid or aliased actual socket endpoint.
    pub(super) fn issue_ram_control_endpoint<'a>(
        &'a self,
        resources: &'a QemuSpawnHostResources,
        command: &crate::QemuLaunchCommand,
        contract: &QemuChildProcessContract,
        preexec: &'a BorrowedPreexecSetup<'_>,
    ) -> Result<Option<IssuedRamControlEndpoint<'a>>, QemuSpawnError> {
        let Some(launch) = command.ram_control() else {
            if resources.ram_control.is_some() {
                return Err(endpoint_refusal("unused RAM pair acquired launch identity"));
            }
            return Ok(None);
        };
        let registration = preexec
            .registration
            .ok_or_else(|| endpoint_refusal("RAM endpoint has no actual registration"))?;
        preexec
            .startup
            .check()
            .map_err(|source| QemuSpawnError::OriginalStartup { source })?;
        let startup = preexec
            .startup
            .record()
            .map_err(|source| QemuSpawnError::PluginStartup { source })?;
        let generation = startup.fields().process_generation;
        if resources.ram_control != Some(launch)
            || resources.process_generation != generation
            || launch.target.owner_generation != generation
            || launch.target != crate::ram_control::target_to_wire(registration.target)
        {
            return Err(endpoint_refusal(
                "RAM endpoint differs from the issued launch target",
            ));
        }
        preexec
            .binding
            .verify_installed_process_purpose(
                contract,
                preexec.supervisor,
                registration,
                generation,
            )
            .map_err(|source| QemuSpawnError::Io {
                operation: "verify issued RAM endpoint lineage",
                source: std::io::Error::other(source),
            })?;
        // This lease was installed before the private pair constructor ran.
        // Retaining its nominal borrow supplies no new allocation or allowance.
        let pair_lease = resources
            .service_lease
            .as_ref()
            .ok_or_else(|| endpoint_refusal("RAM pair has no retained physical service lease"))?;
        let host = resources
            .ram_control_socket
            .as_ref()
            .ok_or_else(|| endpoint_refusal("RAM pair host endpoint was consumed before sealing"))?
            .as_fd();
        let child = self.ram_control_socket.as_fd();
        let identity = observe_endpoint(child).map_err(endpoint_kernel_refusal)?;
        let host_identity = observe_endpoint(host).map_err(endpoint_kernel_refusal)?;
        if identity == host_identity || identity[2] == host_identity[2] {
            return Err(endpoint_refusal("RAM pair aliases one endpoint"));
        }
        preexec
            .startup
            .check()
            .map_err(|source| QemuSpawnError::OriginalStartup { source })?;
        Ok(Some(IssuedRamControlEndpoint {
            child,
            host,
            identity,
            launch,
            binding: preexec.binding,
            registration,
            supervisor: preexec.supervisor,
            _pair_lease: pair_lease,
        }))
    }
}

impl IssuedRamControlEndpoint<'_> {
    /// Rechecks the same original borrower and live endpoint before serialization.
    ///
    /// # Errors
    /// Refuses foreign lineage, changed target/session or actual kernel identity.
    pub(crate) fn verify_for(
        &self,
        binding: &OriginalNativeNodeBinding,
        supervisor: &HostOperationSupervisor,
        registration: &RamControlRegistration,
        process_generation: u64,
    ) -> Result<(), InstalledProcessPurposeError> {
        if !std::ptr::eq(binding, self.binding)
            || !std::ptr::eq(supervisor, self.supervisor)
            || !std::ptr::eq(registration, self.registration)
            || self.launch.target != crate::ram_control::target_to_wire(registration.target)
            || self.launch.target.owner_generation != process_generation
        {
            return Err(InstalledProcessPurposeError::Identity);
        }
        let child =
            observe_endpoint(self.child).map_err(InstalledProcessPurposeError::EndpointKernel)?;
        let host =
            observe_endpoint(self.host).map_err(InstalledProcessPurposeError::EndpointKernel)?;
        if child != self.identity || child == host || child[2] == host[2] {
            return Err(InstalledProcessPurposeError::Identity);
        }
        Ok(())
    }

    /// Encodes corroboration after the actual pair and its containing purpose exist.
    pub(crate) fn corroboration_bytes(&self) -> [u8; RAM_ENDPOINT_CORROBORATION_BYTES] {
        let mut bytes = [0; RAM_ENDPOINT_CORROBORATION_BYTES];
        for (offset, value) in [
            (0, self.identity[0]),
            (8, self.identity[1]),
            (16, self.identity[2]),
            (152, self.launch.target.owner_generation),
            (160, self.launch.target.arena_generation),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[24..56].copy_from_slice(&self.launch.session);
        bytes[56..88].copy_from_slice(&self.launch.target.daemon_epoch);
        bytes[88..120].copy_from_slice(&self.launch.target.owner_id);
        bytes[120..152].copy_from_slice(&self.launch.target.node_id);
        bytes[168] = u8::from(self.launch.target.retained_template);
        bytes
    }
}

fn observe_endpoint(fd: BorrowedFd<'_>) -> Result<[u64; 3], rustix::io::Errno> {
    let metadata = fstat(fd)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Socket
        || socket_domain(fd)? != AddressFamily::UNIX
        || socket_type(fd)? != SocketType::STREAM
    {
        return Err(rustix::io::Errno::INVAL);
    }
    let cookie = socket_cookie(fd)?;
    if metadata.st_ino == 0 || cookie == 0 {
        return Err(rustix::io::Errno::INVAL);
    }
    Ok([metadata.st_dev, metadata.st_ino, cookie])
}

fn endpoint_refusal(reason: &'static str) -> QemuSpawnError {
    QemuSpawnError::Io {
        operation: "bind actual issued RAM endpoint",
        source: std::io::Error::new(std::io::ErrorKind::InvalidInput, reason),
    }
}

fn endpoint_kernel_refusal(source: rustix::io::Errno) -> QemuSpawnError {
    QemuSpawnError::Io {
        operation: "observe actual issued RAM endpoint",
        source: source.into(),
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- actual kernel observation controls localize assertion failures.
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn actual_unix_pair_has_distinct_stable_endpoint_identity() {
        let (host, child) = std::os::unix::net::UnixStream::pair().unwrap();
        let host_identity = observe_endpoint(host.as_fd()).unwrap();
        let child_identity = observe_endpoint(child.as_fd()).unwrap();

        assert_ne!(host_identity, child_identity);
        assert_ne!(host_identity[2], child_identity[2]);
        assert_eq!(observe_endpoint(child.as_fd()).unwrap(), child_identity);
    }

    #[test]
    fn actual_non_socket_cannot_supply_endpoint_corroboration() {
        let file = std::fs::File::open("/dev/null").unwrap();

        assert_eq!(
            observe_endpoint(file.as_fd()),
            Err(rustix::io::Errno::INVAL)
        );
    }
}

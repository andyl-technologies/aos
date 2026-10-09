//! Real stopped native VM descriptor preparation before controller qualification.
//!
//! Preparation deliberately creates no vCPU, RAM mapping, device or run thread.
//! Kernel-object availability is independently observable; it does not authorize
//! execution through a clock path that has no implemented controller ceiling.

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};

use super::{KvmArchitecture, KvmHostProbe, KvmProfileError, probe_native_kvm};

const KVM_CREATE_VM: libc::c_ulong = 0xae01;

/// Owns one actual newly created stopped kernel VM and its system descriptor.
///
/// No vCPU exists and no guest instruction can execute. A native launcher must
/// separately prove complete kernel/emulator mediation and resource admission
/// before realizing vCPUs or entering `KVM_RUN`. There is no TCG fallback.
#[derive(Debug)]
pub struct KvmNativePreparation {
    host: KvmHostProbe,
    vm: File,
    creator_pid: u32,
}

impl KvmNativePreparation {
    /// Returns authentic host capabilities without granting native execution.
    pub const fn host(&self) -> &KvmHostProbe {
        &self.host
    }

    /// Queries a real VM-specific capability without exposing the VM descriptor.
    ///
    /// # Errors
    /// Returns the kernel failure while retaining exclusive native object custody.
    pub fn check_vm_extension(&self, extension: u32) -> Result<i32, KvmProfileError> {
        if std::process::id() != self.creator_pid {
            return Err(KvmProfileError::Identity {
                field: "native VM used outside creating process",
            });
        }
        if self.host.check_extension(105)? == 0 {
            return Err(KvmProfileError::MissingMediation {
                requirement: "VM-specific capability queries are unsupported".to_owned(),
            });
        }
        // SAFETY: KVM_CHECK_EXTENSION uses a scalar capability identifier, not a
        // user-memory pointer. `vm` owns this live newly-created VM descriptor.
        let value =
            unsafe { libc::ioctl(self.vm.as_raw_fd(), 0xae03, libc::c_ulong::from(extension)) };
        if value < 0 {
            return Err(KvmProfileError::Kernel {
                operation: "VM KVM_CHECK_EXTENSION",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(value)
    }
}

/// Opens the real KVM API and creates one stopped native VM with fresh handles.
///
/// This is the operational first step of native backend realization. Missing
/// hardware is returned as `DeviceUnavailable`, independently from later profile
/// refusals. Preparation does not advertise implemented clock containment,
/// architectural capture, deterministic execution or qualified native run.
///
/// # Errors
/// Reports absent or inaccessible KVM, architecture mismatch, failed capability
/// probes, actual VM creation failure, or descriptor setup failure. All acquired
/// kernel objects close on failure; no guest execution has been activated.
pub fn prepare_native_kvm(
    architecture: KvmArchitecture,
) -> Result<KvmNativePreparation, KvmProfileError> {
    let host = probe_native_kvm(architecture)?;
    // SAFETY: KVM_CREATE_VM takes the scalar generic VM type zero. The retained
    // authentic system descriptor is live. Success creates one owned descriptor,
    // transferred exactly once below; failure creates no user-memory references.
    let descriptor = unsafe { libc::ioctl(host.raw_descriptor(), KVM_CREATE_VM, 0) };
    if descriptor < 0 {
        return Err(KvmProfileError::Kernel {
            operation: "KVM_CREATE_VM",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: the successful creation returned a fresh descriptor with sole
    // ownership. Constructing File transfers its cleanup responsibility here.
    let vm = unsafe { File::from_raw_fd(descriptor) };
    rustix::io::fcntl_setfd(&vm, rustix::io::FdFlags::CLOEXEC).map_err(|error| {
        KvmProfileError::Kernel {
            operation: "KVM VM close-on-exec setup",
            source: error.into(),
        }
    })?;
    Ok(KvmNativePreparation {
        host,
        vm,
        creator_pid: std::process::id(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn native_preparation_never_silently_uses_cross_architecture_tcg() {
        let native = KvmArchitecture::native().unwrap();
        let requested = match native {
            KvmArchitecture::X86_64 => KvmArchitecture::Aarch64,
            KvmArchitecture::Aarch64 => KvmArchitecture::X86_64,
        };
        assert!(matches!(
            prepare_native_kvm(requested),
            Err(KvmProfileError::UnsupportedArchitecture { .. })
        ));
    }

    #[test]
    #[ignore = "requires real native /dev/kvm; absence is an operational failure, not qualification"]
    fn hardware_preparation_requires_a_real_fresh_stopped_vm() {
        let preparation = prepare_native_kvm(KvmArchitecture::native().unwrap()).unwrap();
        assert_eq!(preparation.host().api_version(), 12);
        assert!(preparation.host().maximum_vcpus() > 0);
    }
}

//! Authentic Linux KVM system descriptor discovery without native VM activation.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::KvmProfileError;

const KVM_GET_API_VERSION: libc::c_ulong = 0xae00;
const KVM_CHECK_EXTENSION: libc::c_ulong = 0xae03;
const KVM_CAP_ADJUST_CLOCK: libc::c_ulong = 39;
const KVM_CAP_TSC_CONTROL: libc::c_ulong = 60;
const KVM_CAP_GET_TSC_KHZ: libc::c_ulong = 61;
const KVM_CAP_MAX_VCPUS: libc::c_ulong = 66;
const KVM_CAP_IMMEDIATE_EXIT: libc::c_ulong = 136;
const KVM_CAP_COUNTER_OFFSET: libc::c_ulong = 227;

/// Selects an implementation with native, rather than cross-emulated, KVM execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KvmArchitecture {
    /// Uses the x86-64 KVM kernel ABI and guest clock inventory.
    X86_64,
    /// Uses the AArch64 KVM kernel ABI and guest clock inventory.
    Aarch64,
}

impl KvmArchitecture {
    /// Returns the compilation host architecture when native KVM can implement it.
    ///
    /// # Errors
    /// Refuses other native architectures instead of selecting TCG fallback.
    pub fn native() -> Result<Self, KvmProfileError> {
        let kernel = rustix::system::uname();
        let kernel_architecture = kernel.machine().to_string_lossy();
        if kernel_architecture != std::env::consts::ARCH {
            return Err(KvmProfileError::UnsupportedArchitecture {
                architecture: format!(
                    "compiled {} on kernel {kernel_architecture}",
                    std::env::consts::ARCH
                ),
            });
        }
        match kernel_architecture.as_ref() {
            "x86_64" => Ok(Self::X86_64),
            "aarch64" => Ok(Self::Aarch64),
            architecture => Err(KvmProfileError::UnsupportedArchitecture {
                architecture: architecture.to_owned(),
            }),
        }
    }
}

/// Retains a real KVM system descriptor and its authentic baseline capabilities.
///
/// Availability and ordinary offsets/frequency controls do not establish a
/// controller-owned clock, VM-specific capability or exact stopping mechanism.
#[derive(Debug)]
pub struct KvmHostProbe {
    descriptor: File,
    architecture: KvmArchitecture,
    api_version: i32,
    maximum_vcpus: u32,
    immediate_exit: bool,
    clock_adjustment: bool,
    tsc_frequency_control: bool,
    tsc_frequency_query: bool,
    arm_counter_offset: bool,
}

impl KvmHostProbe {
    pub(super) fn raw_descriptor(&self) -> std::os::fd::RawFd {
        self.descriptor.as_raw_fd()
    }

    /// Returns the native architecture of the actual probed host.
    pub const fn architecture(&self) -> KvmArchitecture {
        self.architecture
    }

    /// Returns the actual KVM system API version.
    pub const fn api_version(&self) -> i32 {
        self.api_version
    }

    /// Returns the authentic system vCPU ceiling before per-VM realization checks.
    pub const fn maximum_vcpus(&self) -> u32 {
        self.maximum_vcpus
    }

    /// Reports support for immediate exit at the documented KVM_RUN entry boundary.
    ///
    /// This is not proof of an exact stop or a bounded asynchronous kick latency.
    pub const fn immediate_exit(&self) -> bool {
        self.immediate_exit
    }

    /// Reports ordinary x86 kvmclock timestamp adjustment support.
    pub const fn clock_adjustment(&self) -> bool {
        self.clock_adjustment
    }

    /// Reports ordinary host-dependent TSC frequency control support.
    pub const fn tsc_frequency_control(&self) -> bool {
        self.tsc_frequency_control
    }

    /// Reports support for querying the configured guest TSC frequency.
    pub const fn tsc_frequency_query(&self) -> bool {
        self.tsc_frequency_query
    }

    /// Reports the ARM VM-wide physical and virtual counter-offset capability.
    pub const fn arm_counter_offset(&self) -> bool {
        self.arm_counter_offset
    }

    /// Queries one native system extension without treating its value as qualification.
    ///
    /// # Errors
    /// Returns the actual kernel failure, preserving descriptor ownership.
    pub fn check_extension(&self, extension: u32) -> Result<i32, KvmProfileError> {
        system_ioctl(
            &self.descriptor,
            KVM_CHECK_EXTENSION,
            libc::c_ulong::from(extension),
            "KVM_CHECK_EXTENSION",
        )
    }
}

/// Opens and probes the actual native KVM device before backend realization.
///
/// # Errors
/// Reports device absence/permissions, invalid device identity, a kernel ABI
/// failure or an unsupported native architecture/API. A refused probe is an
/// operational backend failure, never a successful native qualification test.
pub fn probe_native_kvm(requested: KvmArchitecture) -> Result<KvmHostProbe, KvmProfileError> {
    let native = KvmArchitecture::native()?;
    if requested != native {
        return Err(KvmProfileError::UnsupportedArchitecture {
            architecture: format!("requested {requested:?} on native {native:?}"),
        });
    }
    probe_device(Path::new("/dev/kvm"), native)
}

fn probe_device(
    path: &Path,
    architecture: KvmArchitecture,
) -> Result<KvmHostProbe, KvmProfileError> {
    let descriptor = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|source| KvmProfileError::DeviceUnavailable { source })?;
    let metadata = descriptor
        .metadata()
        .map_err(|source| KvmProfileError::DeviceUnavailable { source })?;
    if !metadata.file_type().is_char_device()
        || rustix::fs::major(metadata.rdev()) != 10
        || rustix::fs::minor(metadata.rdev()) != 232
    {
        return Err(KvmProfileError::InvalidDevice);
    }
    let api_version = system_ioctl(&descriptor, KVM_GET_API_VERSION, 0, "KVM_GET_API_VERSION")?;
    if api_version != 12 {
        return Err(KvmProfileError::ApiVersion {
            actual: api_version,
        });
    }
    let extension = |capability| {
        system_ioctl(
            &descriptor,
            KVM_CHECK_EXTENSION,
            capability,
            "KVM_CHECK_EXTENSION",
        )
    };
    let maximum_vcpus = u32::try_from(extension(KVM_CAP_MAX_VCPUS)?).map_err(|_| {
        KvmProfileError::MissingMediation {
            requirement: "invalid native maximum-vCPU capability".to_owned(),
        }
    })?;
    if maximum_vcpus == 0 {
        return Err(KvmProfileError::MissingMediation {
            requirement: "native maximum-vCPU capability unavailable".to_owned(),
        });
    }
    let immediate_exit = extension(KVM_CAP_IMMEDIATE_EXIT)? > 0;
    let clock_adjustment = extension(KVM_CAP_ADJUST_CLOCK)? > 0;
    let tsc_frequency_control = extension(KVM_CAP_TSC_CONTROL)? > 0;
    let tsc_frequency_query = extension(KVM_CAP_GET_TSC_KHZ)? > 0;
    let arm_counter_offset = extension(KVM_CAP_COUNTER_OFFSET)? > 0;
    Ok(KvmHostProbe {
        descriptor,
        architecture,
        api_version,
        maximum_vcpus,
        immediate_exit,
        clock_adjustment,
        tsc_frequency_control,
        tsc_frequency_query,
        arm_counter_offset,
    })
}

fn system_ioctl(
    descriptor: &File,
    request: libc::c_ulong,
    argument: libc::c_ulong,
    operation: &'static str,
) -> Result<i32, KvmProfileError> {
    // SAFETY: this private boundary accepts only Linux KVM system _IO requests
    // with scalar arguments and no user-memory pointers. `descriptor` owns the
    // verified live KVM device throughout the call; successful values are checked.
    let value = unsafe { libc::ioctl(descriptor.as_raw_fd(), request, argument) };
    if value < 0 {
        return Err(KvmProfileError::Kernel {
            operation,
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_file_never_becomes_a_native_kvm_descriptor() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(matches!(
            probe_device(file.path(), KvmArchitecture::X86_64),
            Err(KvmProfileError::InvalidDevice)
        ));
    }

    #[test]
    fn unavailable_device_reports_operational_absence_before_any_ioctl() {
        let directory = tempfile::tempdir().unwrap();
        match probe_device(
            &directory.path().join("missing-kvm"),
            KvmArchitecture::X86_64,
        ) {
            Err(KvmProfileError::DeviceUnavailable { source }) => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound)
            }
            result => panic!("unexpected missing-device probe: {result:?}"),
        }
    }

    #[test]
    fn requested_cross_architecture_never_falls_back_to_emulation() {
        let native = KvmArchitecture::native().unwrap();
        let requested = if native == KvmArchitecture::X86_64 {
            KvmArchitecture::Aarch64
        } else {
            KvmArchitecture::X86_64
        };
        assert!(matches!(
            probe_native_kvm(requested),
            Err(KvmProfileError::UnsupportedArchitecture { .. })
        ));
    }
}

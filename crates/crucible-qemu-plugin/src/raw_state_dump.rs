//! Terminal full-state export for instruction-exact divergence diagnostics.
//!
//! The exporter is armed by the production fingerprint runner for one nonzero
//! aggregate icount. After the ordinary fingerprint sample is published at
//! that exact boundary, it asks patched QEMU to enter a terminal paused state.
//! The paused callback writes a compact binary artifact containing every
//! vCPU's canonical register bytes, every writable guest-RAM range, and the
//! complete serialized non-RAM VMState.

use std::ffi::c_void;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;

use crate::{
    MAX_VCPU_REGISTER_FILE_BYTES, PluginStateDumpConfig, QemuReadVcpuRegsFn,
    resolve_qemu_read_vcpu_regs_symbol,
};

const DUMP_MAGIC: &[u8; 8] = b"CRUCDMP1";
const ERROR_MAGIC: &[u8; 8] = b"CRUCERR1";
const RAM_REGION_NAME_BYTES: usize = 256;

const REQUEST_PAUSE_SYMBOL: &[u8] = b"qemu_plugin_crucible_request_terminal_pause\0";
const RAM_REGIONS_SYMBOL: &[u8] = b"qemu_plugin_crucible_guest_ram_regions\0";
const RAM_COPY_SYMBOL: &[u8] = b"qemu_plugin_crucible_guest_ram_region_copy\0";
const VMSTATE_BEGIN_SYMBOL: &[u8] = b"qemu_plugin_crucible_vmstate_snapshot_begin\0";
const VMSTATE_SIZE_SYMBOL: &[u8] = b"qemu_plugin_crucible_vmstate_snapshot_size\0";
const VMSTATE_COPY_SYMBOL: &[u8] = b"qemu_plugin_crucible_vmstate_snapshot_copy\0";
const VMSTATE_FREE_SYMBOL: &[u8] = b"qemu_plugin_crucible_vmstate_snapshot_free\0";

type TerminalPausedCallback = extern "C" fn(c_int, *mut c_void);
type RequestTerminalPauseFn = extern "C" fn(Option<TerminalPausedCallback>, *mut c_void) -> c_int;
type GuestRamRegionsFn = extern "C" fn(*mut QemuRamRegion, u64, *mut u64) -> c_int;
type GuestRamCopyFn = extern "C" fn(*const QemuRamRegion, u64, *mut c_void, u64) -> c_int;
type VmstateBeginFn = extern "C" fn(*mut *mut c_void) -> c_int;
type VmstateSizeFn = extern "C" fn(*const c_void, *mut u64) -> c_int;
type VmstateCopyFn = extern "C" fn(*const c_void, u64, *mut c_void, u64) -> c_int;
type VmstateFreeFn = extern "C" fn(*mut c_void);

#[repr(C)]
#[derive(Clone, Copy)]
struct QemuRamRegion {
    guest_physical_base: u64,
    length: u64,
    memory_region_offset: u64,
    memory_region_name: [c_char; RAM_REGION_NAME_BYTES],
}

impl Default for QemuRamRegion {
    fn default() -> Self {
        Self {
            guest_physical_base: 0,
            length: 0,
            memory_region_offset: 0,
            memory_region_name: [0; RAM_REGION_NAME_BYTES],
        }
    }
}

#[derive(Clone, Copy)]
struct RawStateApis {
    request_pause: RequestTerminalPauseFn,
    ram_regions: GuestRamRegionsFn,
    ram_copy: GuestRamCopyFn,
    vmstate_begin: VmstateBeginFn,
    vmstate_size: VmstateSizeFn,
    vmstate_copy: VmstateCopyFn,
    vmstate_free: VmstateFreeFn,
    read_vcpu_regs: QemuReadVcpuRegsFn,
}

/// A registration-fixed terminal raw-state dump request.
pub struct PluginRawStateDump {
    target_icount: u64,
    output_path: PathBuf,
    vcpu_count: u32,
    requested: AtomicBool,
    apis: RawStateApis,
}

impl PluginRawStateDump {
    /// Resolves the complete raw-state export capability for one dump request.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRawStateDumpError::CapabilityUnavailable`] when any
    /// patched QEMU raw-state or register export is missing.
    pub fn resolve(
        config: &PluginStateDumpConfig,
        vcpu_count: u32,
    ) -> Result<Self, PluginRawStateDumpError> {
        let apis = RawStateApis {
            request_pause: resolve(REQUEST_PAUSE_SYMBOL, "request terminal pause")?,
            ram_regions: resolve(RAM_REGIONS_SYMBOL, "enumerate guest RAM")?,
            ram_copy: resolve(RAM_COPY_SYMBOL, "copy guest RAM")?,
            vmstate_begin: resolve(VMSTATE_BEGIN_SYMBOL, "begin VMState snapshot")?,
            vmstate_size: resolve(VMSTATE_SIZE_SYMBOL, "size VMState snapshot")?,
            vmstate_copy: resolve(VMSTATE_COPY_SYMBOL, "copy VMState snapshot")?,
            vmstate_free: resolve(VMSTATE_FREE_SYMBOL, "free VMState snapshot")?,
            read_vcpu_regs: resolve_qemu_read_vcpu_regs_symbol().ok_or(
                PluginRawStateDumpError::CapabilityUnavailable {
                    capability: "read vCPU registers",
                },
            )?,
        };
        Ok(Self {
            target_icount: config.target_icount(),
            output_path: config.output_path().to_path_buf(),
            vcpu_count,
            requested: AtomicBool::new(false),
            apis,
        })
    }

    /// Requests the terminal paused export exactly at the configured boundary.
    ///
    /// # Errors
    ///
    /// Returns [`PluginRawStateDumpError`] when the boundary is passed or QEMU
    /// rejects the terminal pause request. Repeated callbacks at the exact
    /// boundary are idempotent while the asynchronous pause is pending.
    pub fn request_if_target(&self, icount: u64) -> Result<(), PluginRawStateDumpError> {
        if icount < self.target_icount {
            return Ok(());
        }
        if icount != self.target_icount {
            return Err(PluginRawStateDumpError::TargetPassed {
                target: self.target_icount,
                observed: icount,
            });
        }
        if self
            .requested
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        let userdata = std::ptr::from_ref(self).cast_mut().cast::<c_void>();
        let status = (self.apis.request_pause)(Some(export_paused), userdata);
        if status != 0 {
            return Err(PluginRawStateDumpError::PauseRejected { status });
        }
        Ok(())
    }

    fn export(&self, terminal_status: c_int) -> Result<(), PluginRawStateDumpError> {
        if terminal_status != 0 {
            return Err(PluginRawStateDumpError::PauseCallbackFailed {
                status: terminal_status,
            });
        }
        let partial = partial_path(&self.output_path);
        let mut output = File::create(&partial).map_err(PluginRawStateDumpError::Io)?;
        output
            .write_all(DUMP_MAGIC)
            .map_err(PluginRawStateDumpError::Io)?;
        write_u64(&mut output, self.target_icount)?;
        write_u32(&mut output, self.vcpu_count)?;
        self.write_registers(&mut output)?;
        self.write_ram(&mut output)?;
        self.write_vmstate(&mut output)?;
        output.sync_all().map_err(PluginRawStateDumpError::Io)?;
        fs::rename(&partial, &self.output_path).map_err(PluginRawStateDumpError::Io)
    }

    fn write_registers(&self, output: &mut File) -> Result<(), PluginRawStateDumpError> {
        for vcpu_id in 0..self.vcpu_count {
            let mut bytes = vec![0_u8; MAX_VCPU_REGISTER_FILE_BYTES];
            let mut length = 0_usize;
            let mut retired = 0_u64;
            let status = (self.apis.read_vcpu_regs)(
                vcpu_id,
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut length,
                &mut retired,
            );
            if status != 0 || length == 0 || length > bytes.len() {
                return Err(PluginRawStateDumpError::RegisterRead {
                    vcpu_id,
                    status,
                    length,
                });
            }
            bytes.truncate(length);
            write_u32(output, vcpu_id)?;
            write_bytes(output, &bytes)?;
        }
        Ok(())
    }

    fn write_ram(&self, output: &mut File) -> Result<(), PluginRawStateDumpError> {
        let mut count = 0_u64;
        let sizing = (self.apis.ram_regions)(std::ptr::null_mut(), 0, &mut count);
        if sizing != -libc::ENOSPC || count == 0 {
            return Err(PluginRawStateDumpError::RamEnumeration { status: sizing });
        }
        let count_usize =
            usize::try_from(count).map_err(|_error| PluginRawStateDumpError::LengthOverflow)?;
        let mut regions = vec![QemuRamRegion::default(); count_usize];
        let status = (self.apis.ram_regions)(regions.as_mut_ptr(), count, &mut count);
        if status != 0 || count != regions.len() as u64 {
            return Err(PluginRawStateDumpError::RamEnumeration { status });
        }
        write_u64(output, count)?;
        for region in &regions {
            write_u64(output, region.guest_physical_base)?;
            write_u64(output, region.length)?;
            let length = usize::try_from(region.length)
                .map_err(|_error| PluginRawStateDumpError::LengthOverflow)?;
            let mut bytes = vec![0_u8; length];
            let status = (self.apis.ram_copy)(region, 0, bytes.as_mut_ptr().cast(), region.length);
            if status != 0 {
                return Err(PluginRawStateDumpError::RamCopy { status });
            }
            output
                .write_all(&bytes)
                .map_err(PluginRawStateDumpError::Io)?;
        }
        Ok(())
    }

    fn write_vmstate(&self, output: &mut File) -> Result<(), PluginRawStateDumpError> {
        let mut snapshot = std::ptr::null_mut();
        let status = (self.apis.vmstate_begin)(&mut snapshot);
        if status != 0 || snapshot.is_null() {
            return Err(PluginRawStateDumpError::VmstateBegin { status });
        }
        let result = (|| {
            let mut length = 0_u64;
            let status = (self.apis.vmstate_size)(snapshot, &mut length);
            if status != 0 || length == 0 {
                return Err(PluginRawStateDumpError::VmstateSize { status });
            }
            let length_usize = usize::try_from(length)
                .map_err(|_error| PluginRawStateDumpError::LengthOverflow)?;
            let mut bytes = vec![0_u8; length_usize];
            let status = (self.apis.vmstate_copy)(snapshot, 0, bytes.as_mut_ptr().cast(), length);
            if status != 0 {
                return Err(PluginRawStateDumpError::VmstateCopy { status });
            }
            write_bytes(output, &bytes)
        })();
        (self.apis.vmstate_free)(snapshot);
        result
    }

    fn write_failure(&self, error: &PluginRawStateDumpError) -> io::Result<()> {
        let partial = partial_path(&self.output_path);
        let mut output = File::create(&partial)?;
        output.write_all(ERROR_MAGIC)?;
        output.write_all(error.to_string().as_bytes())?;
        output.sync_all()?;
        fs::rename(partial, &self.output_path)
    }
}

extern "C" fn export_paused(status: c_int, userdata: *mut c_void) {
    if userdata.is_null() {
        return;
    }
    // SAFETY: `userdata` points at the pinned process-lifetime callback state
    // that owns this exporter. QEMU invokes the callback at most once after a
    // successful request, before plugin teardown releases no callback storage.
    let exporter = unsafe { &*userdata.cast::<PluginRawStateDump>() };
    if let Err(error) = exporter.export(status) {
        let _write_error = exporter.write_failure(&error);
    }
}

fn partial_path(output: &Path) -> PathBuf {
    let mut partial = output.as_os_str().to_owned();
    partial.push(".partial");
    PathBuf::from(partial)
}

fn write_u32(output: &mut File, value: u32) -> Result<(), PluginRawStateDumpError> {
    output
        .write_all(&value.to_le_bytes())
        .map_err(PluginRawStateDumpError::Io)
}

fn write_u64(output: &mut File, value: u64) -> Result<(), PluginRawStateDumpError> {
    output
        .write_all(&value.to_le_bytes())
        .map_err(PluginRawStateDumpError::Io)
}

fn write_bytes(output: &mut File, bytes: &[u8]) -> Result<(), PluginRawStateDumpError> {
    write_u64(
        output,
        u64::try_from(bytes.len()).map_err(|_error| PluginRawStateDumpError::LengthOverflow)?,
    )?;
    output.write_all(bytes).map_err(PluginRawStateDumpError::Io)
}

#[cfg(unix)]
fn resolve<T: Copy>(
    symbol: &'static [u8],
    capability: &'static str,
) -> Result<T, PluginRawStateDumpError> {
    // SAFETY: every name is a static NUL-terminated QEMU export. A non-null
    // result is transmuted to the exact function signature declared by the
    // corresponding patched QEMU public header.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr().cast()) };
    if address.is_null() {
        Err(PluginRawStateDumpError::CapabilityUnavailable { capability })
    } else {
        // SAFETY: the caller pairs each symbol with its header-declared ABI.
        Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&address) })
    }
}

#[cfg(not(unix))]
fn resolve<T: Copy>(
    _symbol: &'static [u8],
    capability: &'static str,
) -> Result<T, PluginRawStateDumpError> {
    Err(PluginRawStateDumpError::CapabilityUnavailable { capability })
}

/// A terminal raw-state export failure.
#[derive(Debug, Error)]
pub enum PluginRawStateDumpError {
    /// A required patched-QEMU capability was unavailable.
    #[error("raw-state capability unavailable: {capability}")]
    CapabilityUnavailable {
        /// Missing capability.
        capability: &'static str,
    },
    /// The callback advanced past the configured target.
    #[error("state-dump target {target} was passed at {observed}")]
    TargetPassed {
        /// Configured target.
        target: u64,
        /// Observed boundary.
        observed: u64,
    },
    /// QEMU rejected the asynchronous terminal pause request.
    #[error("QEMU rejected terminal pause request with status {status}")]
    PauseRejected {
        /// QEMU status.
        status: c_int,
    },
    /// QEMU invoked the paused callback with a failure.
    #[error("QEMU terminal paused callback failed with status {status}")]
    PauseCallbackFailed {
        /// QEMU status.
        status: c_int,
    },
    /// A vCPU register read was incomplete.
    #[error("vCPU {vcpu_id} register read failed: status={status} length={length}")]
    RegisterRead {
        /// vCPU identifier.
        vcpu_id: u32,
        /// QEMU status.
        status: c_int,
        /// Reported byte length.
        length: usize,
    },
    /// Writable RAM enumeration failed.
    #[error("writable RAM enumeration failed with status {status}")]
    RamEnumeration {
        /// QEMU status.
        status: c_int,
    },
    /// A writable RAM copy failed.
    #[error("writable RAM copy failed with status {status}")]
    RamCopy {
        /// QEMU status.
        status: c_int,
    },
    /// Non-RAM VMState snapshot creation failed.
    #[error("VMState snapshot creation failed with status {status}")]
    VmstateBegin {
        /// QEMU status.
        status: c_int,
    },
    /// Non-RAM VMState size discovery failed.
    #[error("VMState snapshot sizing failed with status {status}")]
    VmstateSize {
        /// QEMU status.
        status: c_int,
    },
    /// Non-RAM VMState copying failed.
    #[error("VMState snapshot copy failed with status {status}")]
    VmstateCopy {
        /// QEMU status.
        status: c_int,
    },
    /// A QEMU length could not be represented by this process.
    #[error("raw-state length exceeds host addressability")]
    LengthOverflow,
    /// The dump artifact could not be written atomically.
    #[error("cannot write terminal raw-state artifact: {0}")]
    Io(#[source] io::Error),
}

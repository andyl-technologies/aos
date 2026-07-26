//! Live QEMU adapters for the optional x86_64 white-box doorbell.
//!
//! The adapter recognizes the single-source `out dx,eax` instruction encoding
//! during translation and installs a register-reading instruction callback only
//! on those instructions. At execution it rejects every port except the
//! reserved white-box port, reads the `(pointer, length)` payload registers, and
//! delegates bounded frame decoding to [`crate::PluginWhiteboxDoorbell`].

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicPtr, Ordering};

use crucible_shmem::{MAX_FRAME_DATA, RingHeader, SpscRingError, WhiteboxMarkerEntry};

use crate::{
    GuestMemoryAddressSpace, GuestMemoryRange, GuestMemoryReadError, GuestMemoryReader,
    PluginAppRandomConfig, PluginSwitch, PluginWhiteboxDoorbell, QemuIcountRawFn, QemuPluginId,
    QemuPluginInsn, QemuPluginTb, QemuRequestShutdownFn, WHITEBOX_DOORBELL_X86_64_ABI,
    WHITEBOX_DOORBELL_X86_64_OUT_DX_EAX_BYTES, WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
    WhiteboxDoorbellCapabilities, WhiteboxDoorbellDecodeDiagnostic,
    WhiteboxDoorbellRegistrationPlan, WhiteboxDoorbellSetupResources,
    WhiteboxDoorbellSetupValidation, WhiteboxDoorbellTrapEvent, WhiteboxMarker, WhiteboxMarkerSink,
    WhiteboxMarkerSinkError, handle_whitebox_doorbell_callback,
};

mod app_random;
mod error;
use app_random::LiveAppRandomState;
pub use error::LiveWhiteboxError;

const QEMU_PLUGIN_CB_R_REGS: c_int = 1;
const MAX_LIVE_WHITEBOX_VCPUS: usize = 64;

const REGISTER_TB_TRANS_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_vcpu_tb_trans_cb\0";
const TB_N_INSNS_SYMBOL_C: &[u8] = b"qemu_plugin_tb_n_insns\0";
const TB_GET_INSN_SYMBOL_C: &[u8] = b"qemu_plugin_tb_get_insn\0";
const INSN_DATA_SYMBOL_C: &[u8] = b"qemu_plugin_insn_data\0";
const REGISTER_INSN_EXEC_CB_SYMBOL_C: &[u8] = b"qemu_plugin_register_vcpu_insn_exec_cb\0";
const GET_REGISTERS_SYMBOL_C: &[u8] = b"qemu_plugin_get_registers\0";
const READ_REGISTER_SYMBOL_C: &[u8] = b"qemu_plugin_read_register\0";
const READ_MEMORY_VADDR_SYMBOL_C: &[u8] = b"qemu_plugin_read_memory_vaddr\0";
const WRITE_MEMORY_VADDR_SYMBOL_C: &[u8] = b"qemu_plugin_crucible_write_memory_vaddr\0";
const G_ARRAY_FREE_SYMBOL_C: &[u8] = b"g_array_free\0";
const G_BYTE_ARRAY_NEW_SYMBOL_C: &[u8] = b"g_byte_array_new\0";
const G_BYTE_ARRAY_FREE_SYMBOL_C: &[u8] = b"g_byte_array_free\0";

static LIVE_WHITEBOX_STATE: AtomicPtr<LiveWhiteboxState> = AtomicPtr::new(std::ptr::null_mut());

#[repr(C)]
struct GArray {
    data: *mut c_char,
    len: c_uint,
}

#[repr(C)]
struct GByteArray {
    data: *mut u8,
    len: c_uint,
}

#[repr(C)]
struct QemuPluginRegister {
    _private: [u8; 0],
}

#[repr(C)]
struct QemuPluginRegDescriptor {
    handle: *mut QemuPluginRegister,
    name: *const c_char,
    feature: *const c_char,
}

type QemuVcpuTbTransCbFn = extern "C" fn(QemuPluginId, *mut QemuPluginTb);
type QemuVcpuInsnExecCbFn = extern "C" fn(c_uint, *mut c_void);
type QemuRegisterTbTransCbFn = extern "C" fn(QemuPluginId, Option<QemuVcpuTbTransCbFn>);
type QemuTbNInsnsFn = extern "C" fn(*const QemuPluginTb) -> usize;
type QemuTbGetInsnFn = extern "C" fn(*const QemuPluginTb, usize) -> *mut QemuPluginInsn;
type QemuInsnDataFn = extern "C" fn(*const QemuPluginInsn, *mut c_void, usize) -> usize;
type QemuRegisterInsnExecCbFn =
    extern "C" fn(*mut QemuPluginInsn, Option<QemuVcpuInsnExecCbFn>, c_int, *mut c_void);
type QemuGetRegistersFn = extern "C" fn() -> *mut GArray;
type QemuReadRegisterFn = extern "C" fn(*mut QemuPluginRegister, *mut GByteArray) -> c_int;
type QemuReadMemoryVaddrFn = extern "C" fn(u64, *mut GByteArray, usize) -> bool;
type QemuWriteMemoryVaddrFn = extern "C" fn(u64, *const u8, usize) -> bool;
type GArrayFreeFn = extern "C" fn(*mut GArray, bool) -> *mut c_char;
type GByteArrayNewFn = extern "C" fn() -> *mut GByteArray;
type GByteArrayFreeFn = extern "C" fn(*mut GByteArray, bool) -> *mut u8;

/// Complete upstream-QEMU API table required by the live doorbell adapter.
#[derive(Clone, Copy)]
pub(crate) struct LiveWhiteboxApis {
    register_tb_trans_cb: QemuRegisterTbTransCbFn,
    tb_n_insns: QemuTbNInsnsFn,
    tb_get_insn: QemuTbGetInsnFn,
    insn_data: QemuInsnDataFn,
    register_insn_exec_cb: QemuRegisterInsnExecCbFn,
    get_registers: QemuGetRegistersFn,
    read_register: QemuReadRegisterFn,
    read_memory_vaddr: QemuReadMemoryVaddrFn,
    write_memory_vaddr: QemuWriteMemoryVaddrFn,
    g_array_free: GArrayFreeFn,
    g_byte_array_new: GByteArrayNewFn,
    g_byte_array_free: GByteArrayFreeFn,
}

impl LiveWhiteboxApis {
    /// Resolves every upstream QEMU and GLib symbol before registration.
    ///
    /// # Errors
    ///
    /// Returns [`LiveWhiteboxError::CapabilityUnavailable`] for the first
    /// missing process symbol.
    pub(crate) fn resolve() -> Result<Self, LiveWhiteboxError> {
        Ok(Self {
            register_tb_trans_cb: resolve_symbol(
                REGISTER_TB_TRANS_CB_SYMBOL_C,
                "qemu_plugin_register_vcpu_tb_trans_cb",
            )?,
            tb_n_insns: resolve_symbol(TB_N_INSNS_SYMBOL_C, "qemu_plugin_tb_n_insns")?,
            tb_get_insn: resolve_symbol(TB_GET_INSN_SYMBOL_C, "qemu_plugin_tb_get_insn")?,
            insn_data: resolve_symbol(INSN_DATA_SYMBOL_C, "qemu_plugin_insn_data")?,
            register_insn_exec_cb: resolve_symbol(
                REGISTER_INSN_EXEC_CB_SYMBOL_C,
                "qemu_plugin_register_vcpu_insn_exec_cb",
            )?,
            get_registers: resolve_symbol(GET_REGISTERS_SYMBOL_C, "qemu_plugin_get_registers")?,
            read_register: resolve_symbol(READ_REGISTER_SYMBOL_C, "qemu_plugin_read_register")?,
            read_memory_vaddr: resolve_symbol(
                READ_MEMORY_VADDR_SYMBOL_C,
                "qemu_plugin_read_memory_vaddr",
            )?,
            write_memory_vaddr: resolve_symbol(
                WRITE_MEMORY_VADDR_SYMBOL_C,
                "qemu_plugin_crucible_write_memory_vaddr",
            )?,
            g_array_free: resolve_symbol(G_ARRAY_FREE_SYMBOL_C, "g_array_free")?,
            g_byte_array_new: resolve_symbol(G_BYTE_ARRAY_NEW_SYMBOL_C, "g_byte_array_new")?,
            g_byte_array_free: resolve_symbol(G_BYTE_ARRAY_FREE_SYMBOL_C, "g_byte_array_free")?,
        })
    }
}

#[cfg(unix)]
fn resolve_symbol<T: Copy>(
    symbol_name_c: &'static [u8],
    symbol: &'static str,
) -> Result<T, LiveWhiteboxError> {
    // SAFETY: `symbol_name_c` is a static NUL-terminated name. Every call site
    // supplies the exact function-pointer type declared by QEMU 10.0 or GLib.
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol_name_c.as_ptr().cast()) };
    if address.is_null() {
        Err(LiveWhiteboxError::CapabilityUnavailable { symbol })
    } else {
        // SAFETY: the non-null process symbol has the ABI represented by `T` at
        // the call site, and all supported function pointers are pointer-sized.
        Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&address) })
    }
}

#[cfg(not(unix))]
fn resolve_symbol<T: Copy>(
    _symbol_name_c: &'static [u8],
    symbol: &'static str,
) -> Result<T, LiveWhiteboxError> {
    Err(LiveWhiteboxError::CapabilityUnavailable { symbol })
}

#[derive(Clone, Copy, Default)]
struct LiveWhiteboxRegisters {
    rax: Option<NonNull<QemuPluginRegister>>,
    rcx: Option<NonNull<QemuPluginRegister>>,
    rdx: Option<NonNull<QemuPluginRegister>>,
}

impl LiveWhiteboxRegisters {
    const fn complete(self) -> bool {
        self.rax.is_some() && self.rcx.is_some() && self.rdx.is_some()
    }
}

/// Pinned raw producer view of one ABI-validated white-box marker ring.
#[derive(Debug)]
pub(crate) struct LiveWhiteboxMarkerShmemProducer {
    header: *const RingHeader,
    entries: *mut WhiteboxMarkerEntry,
    capacity: usize,
}

impl LiveWhiteboxMarkerShmemProducer {
    /// Builds a producer retained by the process-lifetime callback owner.
    ///
    /// # Safety
    ///
    /// `header` and the `capacity` entries starting at `entries` must remain
    /// mapped, aligned, and exclusively producer-owned until the callback owner
    /// is destroyed. The host may access them only as the SPSC consumer.
    pub(crate) unsafe fn from_raw_parts(
        header: *const RingHeader,
        entries: *mut WhiteboxMarkerEntry,
        capacity: usize,
    ) -> Self {
        Self {
            header,
            entries,
            capacity,
        }
    }

    fn ring_parts(&mut self) -> (&RingHeader, &mut [WhiteboxMarkerEntry]) {
        // SAFETY: construction requires both raw ranges to remain valid and
        // producer-exclusive. Single-threaded RR serializes trap callbacks.
        unsafe {
            (
                &*self.header,
                std::slice::from_raw_parts_mut(self.entries, self.capacity),
            )
        }
    }

    fn record(
        &mut self,
        current_icount: u64,
        vcpu_index: u32,
        kind: u16,
        payload: &[u8],
    ) -> Result<(), WhiteboxMarkerSinkError> {
        let entry = WhiteboxMarkerEntry::new(current_icount, vcpu_index, kind, payload)
            .map_err(|error| WhiteboxMarkerSinkError::new(error.to_string()))?;
        let (header, entries) = self.ring_parts();
        header
            .enqueue_whitebox_marker(entries, entry)
            .map_err(|error| {
                if matches!(error, SpscRingError::QueueFull { .. }) {
                    WhiteboxMarkerSinkError::new("live white-box marker queue is full")
                } else {
                    WhiteboxMarkerSinkError::new("live white-box marker queue rejected an entry")
                }
            })
    }
}

/// Heap-stable callback state retained by the process-lifetime runtime owner.
pub(crate) struct LiveWhiteboxState {
    apis: LiveWhiteboxApis,
    doorbell: PluginWhiteboxDoorbell,
    registers: [LiveWhiteboxRegisters; MAX_LIVE_WHITEBOX_VCPUS],
    vcpu_count: usize,
    icount_raw: QemuIcountRawFn,
    request_shutdown: QemuRequestShutdownFn,
    marker_sink: LiveMarkerSink,
    app_random: Option<LiveAppRandomState>,
}

impl LiveWhiteboxState {
    /// Builds fail-closed live state after setup collision validation.
    ///
    /// # Errors
    ///
    /// Returns [`LiveWhiteboxError`] when the vCPU count is unsupported or the
    /// safe doorbell registration plan rejects its capabilities or setup state.
    pub(crate) fn new(
        apis: LiveWhiteboxApis,
        setup_attestation: Option<crate::WhiteboxSetupAttestation>,
        vcpu_count: u32,
        icount_raw: QemuIcountRawFn,
        request_shutdown: QemuRequestShutdownFn,
        marker_output: LiveWhiteboxMarkerShmemProducer,
        app_random_config: Option<&PluginAppRandomConfig>,
    ) -> Result<Self, LiveWhiteboxError> {
        if setup_attestation != Some(crate::WhiteboxSetupAttestation::X86Port00e7UnclaimedV1) {
            return Err(LiveWhiteboxError::SetupAttestationMissing);
        }
        let vcpu_count = usize::try_from(vcpu_count).map_err(|_source| {
            LiveWhiteboxError::UnsupportedVcpuCount {
                vcpu_count: u64::from(vcpu_count),
                maximum: MAX_LIVE_WHITEBOX_VCPUS,
            }
        })?;
        if vcpu_count == 0 || vcpu_count > MAX_LIVE_WHITEBOX_VCPUS {
            return Err(LiveWhiteboxError::UnsupportedVcpuCount {
                vcpu_count: vcpu_count as u64,
                maximum: MAX_LIVE_WHITEBOX_VCPUS,
            });
        }

        let doorbell = PluginWhiteboxDoorbell::from_abi(
            PluginSwitch::On,
            WHITEBOX_DOORBELL_X86_64_ABI,
            MAX_FRAME_DATA,
        );
        let validation = WhiteboxDoorbellSetupValidation::validate(
            doorbell.trap(),
            WhiteboxDoorbellSetupResources::from_observed_resources(&[], &[]),
        );
        let capabilities = if app_random_config.is_some() {
            WhiteboxDoorbellCapabilities::bidirectional()
        } else {
            WhiteboxDoorbellCapabilities::guest_to_host()
        };
        let plan = doorbell
            .registration_plan(capabilities, validation)
            .map_err(|source| LiveWhiteboxError::RegistrationPlan {
                message: source.to_string(),
            })?;
        if !matches!(plan, WhiteboxDoorbellRegistrationPlan::Install { .. }) {
            return Err(LiveWhiteboxError::RegistrationPlan {
                message: "enabled live white-box plan did not install a trap".to_owned(),
            });
        }

        let app_random = app_random_config
            .map(|config| {
                doorbell
                    .require_guest_input_capability(capabilities)
                    .map(|capability| LiveAppRandomState::new(config, capability))
            })
            .transpose()
            .map_err(|source| LiveWhiteboxError::RegistrationPlan {
                message: source.to_string(),
            })?;

        Ok(Self {
            apis,
            doorbell,
            registers: [LiveWhiteboxRegisters::default(); MAX_LIVE_WHITEBOX_VCPUS],
            vcpu_count,
            icount_raw,
            request_shutdown,
            marker_sink: LiveMarkerSink {
                output: marker_output,
            },
            app_random,
        })
    }

    /// Publishes the state and registers translation callbacks.
    ///
    /// # Errors
    ///
    /// Returns [`LiveWhiteboxError::StateAlreadyPublished`] when another live
    /// white-box owner is already installed.
    pub(crate) fn register(&mut self, plugin_id: QemuPluginId) -> Result<(), LiveWhiteboxError> {
        LIVE_WHITEBOX_STATE
            .compare_exchange(
                std::ptr::null_mut(),
                std::ptr::from_mut(self),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_existing| LiveWhiteboxError::StateAlreadyPublished)?;
        (self.apis.register_tb_trans_cb)(
            plugin_id,
            Some(crucible_qemu_plugin_live_whitebox_tb_trans_cb),
        );
        Ok(())
    }

    fn initialize_vcpu(&mut self, vcpu_index: usize) -> Result<(), LiveWhiteboxError> {
        if vcpu_index >= self.vcpu_count {
            return Err(LiveWhiteboxError::UnexpectedVcpu {
                vcpu_index,
                vcpu_count: self.vcpu_count,
            });
        }

        let array = (self.apis.get_registers)();
        let Some(array) = NonNull::new(array) else {
            return Err(LiveWhiteboxError::RegisterListUnavailable { vcpu_index });
        };
        // QEMU retains the descriptor array for the duration of this callback.
        // SAFETY: `data` contains exactly `len` initialized register descriptors.
        let descriptors = unsafe {
            std::slice::from_raw_parts(
                array.as_ref().data.cast::<QemuPluginRegDescriptor>(),
                array.as_ref().len as usize,
            )
        };
        let mut registers = LiveWhiteboxRegisters::default();
        for descriptor in descriptors {
            if descriptor.name.is_null() {
                continue;
            }
            // SAFETY: QEMU documents descriptor names as valid NUL-terminated
            // strings retained for the plugin lifetime.
            let raw_name = unsafe { CStr::from_ptr(descriptor.name) }.to_bytes();
            let name = raw_name.strip_prefix(b"%").unwrap_or(raw_name);
            let handle = NonNull::new(descriptor.handle);
            match name {
                b"rax" => registers.rax = handle,
                b"rcx" => registers.rcx = handle,
                b"rdx" => registers.rdx = handle,
                _ => {}
            }
        }
        (self.apis.g_array_free)(array.as_ptr(), true);
        if !registers.complete() {
            return Err(LiveWhiteboxError::RequiredRegistersUnavailable { vcpu_index });
        }
        self.registers[vcpu_index] = registers;
        Ok(())
    }

    fn service(&mut self, vcpu_index: usize) -> Result<(), LiveWhiteboxError> {
        if vcpu_index >= self.vcpu_count {
            return Err(LiveWhiteboxError::UnexpectedVcpu {
                vcpu_index,
                vcpu_count: self.vcpu_count,
            });
        }
        let registers = self.registers[vcpu_index];
        let port = self.read_register_u64(
            registers
                .rdx
                .ok_or(LiveWhiteboxError::RequiredRegistersUnavailable { vcpu_index })?,
        )? as u16;
        if port != WHITEBOX_DOORBELL_X86_64_RESERVED_PORT {
            return Ok(());
        }
        let address = self.read_register_u64(
            registers
                .rax
                .ok_or(LiveWhiteboxError::RequiredRegistersUnavailable { vcpu_index })?,
        )?;
        let len_u64 = self.read_register_u64(
            registers
                .rcx
                .ok_or(LiveWhiteboxError::RequiredRegistersUnavailable { vcpu_index })?,
        )?;
        let len = usize::try_from(len_u64)
            .map_err(|_source| LiveWhiteboxError::PayloadLengthOverflow { len: len_u64 })?;
        let current_icount = (self.icount_raw)();
        let event = WhiteboxDoorbellTrapEvent::from_register_pointer_length(
            vcpu_index as u32,
            current_icount,
            GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, address, len),
        );
        let mut reader = LiveGuestMemoryReader { apis: self.apis };
        let payload = reader
            .read_guest_memory(
                event.vcpu_index(),
                event.current_icount(),
                event.payload_range(),
            )
            .map_err(|source| LiveWhiteboxError::Callback {
                message: source.to_string(),
            })?;
        if app_random::is_request(&payload) {
            self.handle_app_random(&mut reader, event, current_icount, vcpu_index)
        } else {
            handle_whitebox_doorbell_callback(
                &self.doorbell,
                &mut reader,
                &mut self.marker_sink,
                event,
            )
            .map(|_marker| ())
            .map_err(|source| LiveWhiteboxError::Callback {
                message: source.to_string(),
            })
        }
    }

    fn read_register_u64(
        &self,
        handle: NonNull<QemuPluginRegister>,
    ) -> Result<u64, LiveWhiteboxError> {
        let array = (self.apis.g_byte_array_new)();
        let Some(array) = NonNull::new(array) else {
            return Err(LiveWhiteboxError::ByteArrayAllocation);
        };
        let size = (self.apis.read_register)(handle.as_ptr(), array.as_ptr());
        if size <= 0 {
            (self.apis.g_byte_array_free)(array.as_ptr(), true);
            return Err(LiveWhiteboxError::RegisterRead);
        }
        let bytes = {
            // GLib retains the array until the explicit free below.
            // SAFETY: QEMU sets `data` and `len` to the initialized register bytes.
            unsafe { std::slice::from_raw_parts(array.as_ref().data, array.as_ref().len as usize) }
        };
        let mut value = 0_u64;
        for (shift, byte) in bytes.iter().copied().take(8).enumerate() {
            value |= u64::from(byte) << (shift * 8);
        }
        (self.apis.g_byte_array_free)(array.as_ptr(), true);
        Ok(value)
    }

    fn fail_loud(&self, error: &LiveWhiteboxError) {
        let message = format!("crucible-qemu-plugin: live white-box callback failed: {error}\n");
        let _written = write_stderr(message.as_bytes());
        (self.request_shutdown)(1);
    }
}

struct LiveGuestMemoryReader {
    apis: LiveWhiteboxApis,
}

impl GuestMemoryReader for LiveGuestMemoryReader {
    fn read_guest_memory(
        &mut self,
        _vcpu_index: u32,
        _current_icount: u64,
        range: GuestMemoryRange,
    ) -> Result<Vec<u8>, GuestMemoryReadError> {
        if !matches!(range.address_space(), GuestMemoryAddressSpace::Virtual) {
            return Err(GuestMemoryReadError::new(
                "live white-box adapter requires a virtual payload range",
            ));
        }
        let array = (self.apis.g_byte_array_new)();
        let Some(array) = NonNull::new(array) else {
            return Err(GuestMemoryReadError::new(
                "GLib byte-array allocation failed",
            ));
        };
        let read =
            (self.apis.read_memory_vaddr)(range.guest_address(), array.as_ptr(), range.len());
        if !read {
            (self.apis.g_byte_array_free)(array.as_ptr(), true);
            return Err(GuestMemoryReadError::new(
                "qemu_plugin_read_memory_vaddr failed",
            ));
        }
        let bytes = {
            // The returned bytes are copied before the GLib array is freed.
            // SAFETY: QEMU sets `data` and `len` to the initialized memory result.
            unsafe { std::slice::from_raw_parts(array.as_ref().data, array.as_ref().len as usize) }
        }
        .to_vec();
        (self.apis.g_byte_array_free)(array.as_ptr(), true);
        Ok(bytes)
    }
}

struct LiveMarkerSink {
    output: LiveWhiteboxMarkerShmemProducer,
}

fn write_stderr(bytes: &[u8]) -> Result<(), String> {
    // SAFETY: `bytes` is a valid readable slice for the duration of the call.
    // The fixed descriptor is stderr, and no ownership is transferred.
    let written = unsafe { libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len()) };
    if written < 0 {
        Err(format!(
            "write live white-box diagnostic to stderr failed: {}",
            std::io::Error::last_os_error()
        ))
    } else if written as usize != bytes.len() {
        Err(format!(
            "short live white-box diagnostic write: wrote {written} of {} bytes",
            bytes.len()
        ))
    } else {
        Ok(())
    }
}

impl WhiteboxMarkerSink for LiveMarkerSink {
    fn record_whitebox_marker(
        &mut self,
        marker: &WhiteboxMarker,
    ) -> Result<(), WhiteboxMarkerSinkError> {
        self.output.record(
            marker.marker_icount(),
            marker.vcpu_index(),
            marker.kind(),
            marker.payload(),
        )
    }

    fn record_whitebox_decode_diagnostic(
        &mut self,
        _diagnostic: &WhiteboxDoorbellDecodeDiagnostic,
    ) -> Result<(), WhiteboxMarkerSinkError> {
        Ok(())
    }
}

extern "C" fn crucible_qemu_plugin_live_whitebox_tb_trans_cb(
    _plugin_id: QemuPluginId,
    tb: *mut QemuPluginTb,
) {
    let Some(mut state) = NonNull::new(LIVE_WHITEBOX_STATE.load(Ordering::Acquire)) else {
        return;
    };
    if tb.is_null() {
        return;
    }
    // SAFETY: publication retains the state for QEMU's process lifetime, and
    // the validated single-threaded RR execution model serializes callbacks.
    let state = unsafe { state.as_mut() };
    let count = (state.apis.tb_n_insns)(tb);
    for index in 0..count {
        let insn = (state.apis.tb_get_insn)(tb, index);
        if insn.is_null() {
            continue;
        }
        let mut bytes = [0_u8; 4];
        let copied = (state.apis.insn_data)(insn, bytes.as_mut_ptr().cast(), bytes.len());
        if bytes[..copied.min(bytes.len())] == WHITEBOX_DOORBELL_X86_64_OUT_DX_EAX_BYTES {
            (state.apis.register_insn_exec_cb)(
                insn,
                Some(crucible_qemu_plugin_live_whitebox_insn_exec_cb),
                QEMU_PLUGIN_CB_R_REGS,
                std::ptr::null_mut(),
            );
        }
    }
}

extern "C" fn crucible_qemu_plugin_live_whitebox_insn_exec_cb(
    vcpu_index: c_uint,
    _userdata: *mut c_void,
) {
    let Some(mut state) = NonNull::new(LIVE_WHITEBOX_STATE.load(Ordering::Acquire)) else {
        return;
    };
    // SAFETY: publication retains the state for QEMU's process lifetime, and
    // the validated single-threaded RR execution model serializes callbacks.
    let state = unsafe { state.as_mut() };
    if let Err(error) = state.service(vcpu_index as usize) {
        state.fail_loud(&error);
    }
}

/// Initializes the register handles for one live vCPU.
pub(crate) extern "C" fn crucible_qemu_plugin_live_whitebox_vcpu_init_cb(
    _plugin_id: QemuPluginId,
    vcpu_index: c_uint,
) {
    let Some(mut state) = NonNull::new(LIVE_WHITEBOX_STATE.load(Ordering::Acquire)) else {
        return;
    };
    // SAFETY: publication retains the state for QEMU's process lifetime, and
    // the validated single-threaded RR execution model serializes callbacks.
    let state = unsafe { state.as_mut() };
    if let Err(error) = state.initialize_vcpu(vcpu_index as usize) {
        state.fail_loud(&error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_marker_producer_publishes_exact_entry_to_shmem() {
        let header = RingHeader::new();
        let mut entries = vec![WhiteboxMarkerEntry::default(); 4];
        {
            // SAFETY: the test-owned header and entry array outlive the producer,
            // and no other producer accesses them.
            let mut producer = unsafe {
                LiveWhiteboxMarkerShmemProducer::from_raw_parts(
                    std::ptr::from_ref(&header),
                    entries.as_mut_ptr(),
                    entries.len(),
                )
            };

            if let Err(error) = producer.record(913, 2, 4, b"MARK") {
                panic!("live marker producer should enqueue: {error}");
            }
        }

        let entry = match header.dequeue_whitebox_marker(&entries) {
            Ok(Some(entry)) => entry,
            Ok(None) => panic!("live marker ring should contain one entry"),
            Err(error) => panic!("live marker ring should dequeue: {error}"),
        };
        assert_eq!(entry.current_icount(), 913);
        assert_eq!(entry.vcpu_index(), 2);
        assert_eq!(entry.kind(), 4);
        assert_eq!(entry.payload(), b"MARK");
        assert_eq!(entry.validate(), Ok(entry));
    }

    #[test]
    fn live_marker_producer_fails_loud_when_queue_is_full() {
        let header = RingHeader::new();
        let mut entries = vec![WhiteboxMarkerEntry::default(); 2];
        // SAFETY: the test-owned header and entry array outlive the producer,
        // and no other producer accesses them.
        let mut producer = unsafe {
            LiveWhiteboxMarkerShmemProducer::from_raw_parts(
                std::ptr::from_ref(&header),
                entries.as_mut_ptr(),
                entries.len(),
            )
        };

        if let Err(error) = producer.record(1, 0, 4, b"a") {
            panic!("first marker should enqueue: {error}");
        }
        if let Err(error) = producer.record(2, 0, 4, b"b") {
            panic!("second marker should enqueue: {error}");
        }
        let error = match producer.record(3, 0, 4, b"c") {
            Ok(()) => panic!("full marker ring must reject a third entry"),
            Err(error) => error,
        };
        assert!(error.message().contains("queue is full"));
    }
}

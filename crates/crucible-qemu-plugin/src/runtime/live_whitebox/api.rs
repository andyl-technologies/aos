//! Upstream QEMU and GLib API bindings used by the live white-box adapter.

use std::os::raw::{c_char, c_int, c_uint, c_void};

use crate::{QemuPluginId, QemuPluginInsn, QemuPluginTb};

use super::LiveWhiteboxError;

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

#[repr(C)]
pub(super) struct GArray {
    pub(super) data: *mut c_char,
    pub(super) len: c_uint,
}

#[repr(C)]
pub(super) struct GByteArray {
    pub(super) data: *mut u8,
    pub(super) len: c_uint,
}

#[repr(C)]
pub(super) struct QemuPluginRegister {
    _private: [u8; 0],
}

#[repr(C)]
pub(super) struct QemuPluginRegDescriptor {
    pub(super) handle: *mut QemuPluginRegister,
    pub(super) name: *const c_char,
    pub(super) feature: *const c_char,
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
    pub(super) register_tb_trans_cb: QemuRegisterTbTransCbFn,
    pub(super) tb_n_insns: QemuTbNInsnsFn,
    pub(super) tb_get_insn: QemuTbGetInsnFn,
    pub(super) insn_data: QemuInsnDataFn,
    pub(super) register_insn_exec_cb: QemuRegisterInsnExecCbFn,
    pub(super) get_registers: QemuGetRegistersFn,
    pub(super) read_register: QemuReadRegisterFn,
    pub(super) read_memory_vaddr: QemuReadMemoryVaddrFn,
    pub(super) write_memory_vaddr: QemuWriteMemoryVaddrFn,
    pub(super) g_array_free: GArrayFreeFn,
    pub(super) g_byte_array_new: GByteArrayNewFn,
    pub(super) g_byte_array_free: GByteArrayFreeFn,
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

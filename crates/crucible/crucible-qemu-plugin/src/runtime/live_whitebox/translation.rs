//! Exact whitebox trap instrumentation within the original translation owner.

use super::api::{
    QemuInsnDataFn, QemuRegisterInsnExecCbFn, QemuRegisterTbExecCbFn, QemuTbGetInsnFn,
    QemuTbNInsnsFn,
};
use super::*;

pub(super) struct TranslationApis {
    tb_n_insns: QemuTbNInsnsFn,
    tb_get_insn: QemuTbGetInsnFn,
    insn_data: QemuInsnDataFn,
    register_tb_exec_cb: QemuRegisterTbExecCbFn,
    register_insn_exec_cb: QemuRegisterInsnExecCbFn,
}

impl From<LiveWhiteboxApis> for TranslationApis {
    fn from(apis: LiveWhiteboxApis) -> Self {
        Self {
            tb_n_insns: apis.tb_n_insns,
            tb_get_insn: apis.tb_get_insn,
            insn_data: apis.insn_data,
            register_tb_exec_cb: apis.register_tb_exec_cb,
            register_insn_exec_cb: apis.register_insn_exec_cb,
        }
    }
}

impl TranslationApis {
    pub(super) fn instrument(
        &self,
        architecture: QemuPluginTargetArchitecture,
        tb: *mut QemuPluginTb,
    ) -> Result<(), LiveWhiteboxError> {
        super::super::live_callbacks::time_ownership_witness::observe_translation(tb);
        let count = (self.tb_n_insns)(tb);
        let mut registered_entry_callback = false;
        for index in 0..count {
            let insn = (self.tb_get_insn)(tb, index);
            if insn.is_null() {
                continue;
            }
            let mut bytes = [0_u8; 4];
            let copied = (self.insn_data)(insn, bytes.as_mut_ptr().cast(), bytes.len());
            let trap_bytes: &[u8] = match architecture {
                QemuPluginTargetArchitecture::X86_64 => &WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES,
                QemuPluginTargetArchitecture::Aarch64 => &WHITEBOX_DOORBELL_AARCH64_HINT_BYTES,
            };
            if bytes[..copied.min(bytes.len())] == *trap_bytes {
                let location = LiveWhiteboxInstructionLocation::new(count, index)?;
                if !registered_entry_callback {
                    (self.register_tb_exec_cb)(
                        tb,
                        Some(crucible_qemu_plugin_live_whitebox_tb_exec_cb),
                        QEMU_PLUGIN_CB_NO_REGS,
                        location.tb_userdata(),
                    );
                    registered_entry_callback = true;
                }
                (self.register_insn_exec_cb)(
                    insn,
                    Some(crucible_qemu_plugin_live_whitebox_insn_exec_cb),
                    QEMU_PLUGIN_CB_R_REGS,
                    location.into_userdata(),
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::QemuPluginInsn;

    thread_local! {
        static ENTRY: RefCell<Vec<(usize, c_int, usize)>> = const { RefCell::new(Vec::new()) };
        static TRAPS: RefCell<Vec<(usize, usize, c_int, usize)>> = const { RefCell::new(Vec::new()) };
    }

    extern "C" fn tb_length(_tb: *const QemuPluginTb) -> usize {
        3
    }

    extern "C" fn instruction(_tb: *const QemuPluginTb, index: usize) -> *mut QemuPluginInsn {
        (index + 1) as *mut QemuPluginInsn
    }

    extern "C" fn bytes(
        insn: *const QemuPluginInsn,
        destination: *mut c_void,
        len: usize,
    ) -> usize {
        let bytes = if insn as usize == 2 || insn as usize == 3 {
            WHITEBOX_DOORBELL_X86_64_OUT_IMM8_AL_BYTES.as_slice()
        } else {
            &[0x90]
        };
        assert!(len >= bytes.len());
        // SAFETY: the production instrumentation supplies its writable four-byte
        // local buffer; these exact instruction bytes fit within that buffer.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), destination.cast(), bytes.len()) };
        bytes.len()
    }

    extern "C" fn entry(
        _tb: *mut QemuPluginTb,
        callback: Option<extern "C" fn(c_uint, *mut c_void)>,
        flags: c_int,
        userdata: *mut c_void,
    ) {
        let callback = callback.unwrap_or_else(|| panic!("original entry callback required"));
        ENTRY.with_borrow_mut(|rows| rows.push((callback as usize, flags, userdata as usize)));
    }

    extern "C" fn trap(
        insn: *mut QemuPluginInsn,
        callback: Option<extern "C" fn(c_uint, *mut c_void)>,
        flags: c_int,
        userdata: *mut c_void,
    ) {
        let callback = callback.unwrap_or_else(|| panic!("original trap callback required"));
        TRAPS.with_borrow_mut(|rows| {
            rows.push((insn as usize, callback as usize, flags, userdata as usize));
        });
    }

    pub(crate) fn assert_original_translation() {
        ENTRY.with_borrow_mut(Vec::clear);
        TRAPS.with_borrow_mut(Vec::clear);
        let apis = TranslationApis {
            tb_n_insns: tb_length,
            tb_get_insn: instruction,
            insn_data: bytes,
            register_tb_exec_cb: entry,
            register_insn_exec_cb: trap,
        };

        apis.instrument(
            QemuPluginTargetArchitecture::X86_64,
            std::ptr::dangling_mut::<QemuPluginTb>(),
        )
        .unwrap_or_else(|error| panic!("original trap instrumentation failed: {error}"));

        ENTRY.with_borrow(|rows| {
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].0,
                crucible_qemu_plugin_live_whitebox_tb_exec_cb as *const () as usize
            );
            assert_eq!(rows[0].1, QEMU_PLUGIN_CB_NO_REGS);
            assert_eq!(
                LiveWhiteboxInstructionLocation::tb_insns_from_userdata(rows[0].2 as *mut c_void)
                    .unwrap_or_else(|error| panic!("entry identity invalid: {error}")),
                3
            );
        });
        TRAPS.with_borrow(|rows| {
            assert_eq!(rows.len(), 2);
            for (index, row) in rows.iter().enumerate() {
                assert_eq!(row.0, index + 2);
                assert_eq!(
                    row.1,
                    crucible_qemu_plugin_live_whitebox_insn_exec_cb as *const () as usize
                );
                assert_eq!(row.2, QEMU_PLUGIN_CB_R_REGS);
                let location = LiveWhiteboxInstructionLocation::from_userdata(row.3 as *mut c_void)
                    .unwrap_or_else(|error| panic!("trap identity invalid: {error}"));
                assert_eq!(
                    location,
                    LiveWhiteboxInstructionLocation::new(3, index + 1)
                        .unwrap_or_else(|error| panic!("expected trap identity invalid: {error}"))
                );
            }
        });
    }

    #[test]
    fn original_whitebox_translation_installs_exact_traps_and_one_entry() {
        let witness =
            crate::runtime::live_callbacks::time_ownership_witness::scoped_translation_witness();
        assert_original_translation();
        assert_eq!(witness.instrumentations(), 1);
    }
}

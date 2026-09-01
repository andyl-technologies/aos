//! Per-vCPU register-file and round-robin cursor introspection.
//!
//! The N-vCPU execution fingerprint needs black-box state from every vCPU, not
//! just QEMU's current CPU. This module wraps the patched QEMU introspection
//! exports in safe Rust: one capability reads an arbitrary vCPU's architectural
//! register file, the other reads the round-robin cursor position inside the
//! pinned `rr_switch_quantum`. The wrapper collects inputs in ascending vCPU
//! order and does not mutate plugin scheduling, virtual-time, or guest state.

use std::os::raw::c_int;

use crucible_protocol::{
    PluginNvcpuFingerprintSnapshot, PluginNvcpuFingerprintSnapshotError,
    PluginRoundRobinCursorSnapshot, PluginVcpuRegisterSnapshot,
};
use thiserror::Error;

use crate::RoundRobinRunState;

/// Required QEMU plugin extension symbol for per-vCPU register-file reads.
pub const QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL: &str = "qemu_plugin_read_vcpu_regs";
/// Required QEMU plugin extension symbol for round-robin cursor reads.
pub const QEMU_PLUGIN_RR_CURSOR_SYMBOL: &str = "qemu_plugin_rr_cursor";
/// Compatibility symbol carried by the AOS QEMU fingerprint helper patch.
pub const QEMU_PLUGIN_CRUCIBLE_GET_VCPU_REGISTERS_SYMBOL: &str =
    "qemu_plugin_crucible_get_vcpu_registers";
/// Compatibility symbol carried by the AOS QEMU fingerprint helper patch.
pub const QEMU_PLUGIN_CRUCIBLE_READ_VCPU_REGISTER_SYMBOL: &str =
    "qemu_plugin_crucible_read_vcpu_register";
/// Compatibility symbol carried by the AOS QEMU fingerprint helper patch.
pub const QEMU_PLUGIN_CRUCIBLE_RR_CURRENT_VCPU_SYMBOL: &str =
    "qemu_plugin_crucible_rr_current_vcpu";
/// Compatibility symbol carried by the AOS QEMU fingerprint helper patch.
pub const QEMU_PLUGIN_CRUCIBLE_RR_CURSOR_POSITION_SYMBOL: &str =
    "qemu_plugin_crucible_rr_cursor_position";
/// Compatibility symbol carried by the AOS QEMU fingerprint helper patch.
pub const QEMU_PLUGIN_CRUCIBLE_RR_SWITCH_QUANTUM_SYMBOL: &str =
    "qemu_plugin_crucible_rr_switch_quantum";
/// Fixed byte length used by the execution-fingerprint register digest.
pub const PLUGIN_REGISTER_DIGEST_BYTES: usize = 32;
/// Maximum canonical register-file byte payload accepted from the QEMU adapter.
pub const MAX_VCPU_REGISTER_FILE_BYTES: usize = 4096;

/// QEMU's side-effect-free per-vCPU register-file read function.
///
/// The patched adapter writes canonical architectural register bytes for
/// `vcpu_id` into `out_register_bytes`, stores the byte count in
/// `out_register_len`, stores an adapter-provided retired-instruction stamp in
/// `out_retired_instruction_count`, and returns zero on success.
pub type QemuReadVcpuRegsFn = extern "C" fn(u32, *mut u8, usize, *mut usize, *mut u64) -> c_int;

/// QEMU's side-effect-free round-robin cursor read function.
///
/// The patched adapter writes [`QemuRoundRobinCursor`] and returns zero on
/// success.
pub type QemuReadRrCursorFn = extern "C" fn(*mut QemuRoundRobinCursor) -> c_int;

/// Raw round-robin cursor payload returned by QEMU.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QemuRoundRobinCursor {
    /// Current vCPU in QEMU's single-threaded round-robin cursor.
    pub current_vcpu: u64,
    /// Retired node-icount position inside the pinned RR quantum.
    pub cursor_position: u64,
    /// Pinned round-robin switch quantum in node-icount units.
    pub rr_switch_quantum: u64,
}

/// Digest of one vCPU's architectural register file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginVcpuRegisterDigest {
    vcpu_id: u32,
    register_digest: [u8; PLUGIN_REGISTER_DIGEST_BYTES],
    register_file_bytes: usize,
    retired_instruction_count: u64,
}

impl PluginVcpuRegisterDigest {
    /// Builds a register digest record.
    ///
    /// # Errors
    ///
    /// Returns [`VcpuIntrospectionError::EmptyRegisterFile`] when the register
    /// byte count is zero, or [`VcpuIntrospectionError::RegisterFileTooLarge`]
    /// when it exceeds [`MAX_VCPU_REGISTER_FILE_BYTES`].
    pub fn new(
        vcpu_id: u32,
        register_file: &[u8],
        retired_instruction_count: u64,
    ) -> Result<Self, VcpuIntrospectionError> {
        if register_file.is_empty() {
            return Err(VcpuIntrospectionError::EmptyRegisterFile { vcpu_id });
        }
        if register_file.len() > MAX_VCPU_REGISTER_FILE_BYTES {
            return Err(VcpuIntrospectionError::RegisterFileTooLarge {
                vcpu_id,
                len: register_file.len(),
                max: MAX_VCPU_REGISTER_FILE_BYTES,
            });
        }
        Ok(Self {
            vcpu_id,
            register_digest: digest_register_file(vcpu_id, register_file),
            register_file_bytes: register_file.len(),
            retired_instruction_count,
        })
    }

    /// Returns the vCPU identifier.
    #[must_use]
    pub const fn vcpu_id(&self) -> u32 {
        self.vcpu_id
    }

    /// Returns the fixed-width architectural register digest.
    #[must_use]
    pub const fn register_digest(&self) -> &[u8; PLUGIN_REGISTER_DIGEST_BYTES] {
        &self.register_digest
    }

    /// Returns the number of canonical register-file bytes read.
    #[must_use]
    pub const fn register_file_bytes(&self) -> usize {
        self.register_file_bytes
    }

    /// Returns the adapter-provided retired-instruction stamp for the registers.
    #[must_use]
    pub const fn retired_instruction_count(&self) -> u64 {
        self.retired_instruction_count
    }

    /// Converts this plugin register digest into the host/plugin protocol shape.
    ///
    /// # Errors
    ///
    /// Returns [`PluginNvcpuFingerprintSnapshotError`] when the register byte
    /// count violates the shared snapshot contract.
    pub const fn to_protocol_snapshot(
        &self,
    ) -> Result<PluginVcpuRegisterSnapshot, PluginNvcpuFingerprintSnapshotError> {
        PluginVcpuRegisterSnapshot::new(
            self.vcpu_id,
            self.register_digest,
            self.register_file_bytes,
            self.retired_instruction_count,
        )
    }
}

/// Round-robin cursor state included in N-vCPU fingerprint inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginRoundRobinCursor {
    current_vcpu: u64,
    cursor_position: u64,
    quantum_remaining: u64,
    rr_switch_quantum: u64,
}

impl PluginRoundRobinCursor {
    /// Builds and validates a round-robin cursor snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`VcpuIntrospectionError`] when the vCPU count is zero, the
    /// current vCPU is outside `0..vcpu_count`, the quantum is zero, or the
    /// cursor position reaches the pinned quantum boundary.
    pub const fn new(
        current_vcpu: u64,
        cursor_position: u64,
        rr_switch_quantum: u64,
        vcpu_count: u32,
    ) -> Result<Self, VcpuIntrospectionError> {
        if vcpu_count == 0 {
            return Err(VcpuIntrospectionError::ZeroVcpuCount);
        }
        if current_vcpu >= vcpu_count as u64 {
            return Err(VcpuIntrospectionError::CurrentVcpuOutOfRange {
                current_vcpu,
                vcpu_count,
            });
        }
        if rr_switch_quantum == 0 {
            return Err(VcpuIntrospectionError::ZeroSwitchQuantum);
        }
        if cursor_position >= rr_switch_quantum {
            return Err(VcpuIntrospectionError::CursorPastQuantum {
                cursor_position,
                rr_switch_quantum,
            });
        }
        Ok(Self {
            current_vcpu,
            cursor_position,
            quantum_remaining: rr_switch_quantum - cursor_position,
            rr_switch_quantum,
        })
    }

    /// Builds a cursor snapshot from the plugin's local RUN cursor.
    #[must_use]
    pub fn from_run_state(run_state: RoundRobinRunState) -> Self {
        Self {
            current_vcpu: u64::from(run_state.current_vcpu()),
            cursor_position: run_state.cursor_position(),
            quantum_remaining: run_state.remaining_in_quantum(),
            rr_switch_quantum: run_state.rr_switch_quantum(),
        }
    }

    /// Returns the current vCPU.
    #[must_use]
    pub const fn current_vcpu(self) -> u64 {
        self.current_vcpu
    }

    /// Returns the retired node-icount position inside the current quantum.
    #[must_use]
    pub const fn cursor_position(self) -> u64 {
        self.cursor_position
    }

    /// Returns the remaining node-icount budget in the current quantum.
    #[must_use]
    pub const fn quantum_remaining(self) -> u64 {
        self.quantum_remaining
    }

    /// Returns the pinned switch quantum.
    #[must_use]
    pub const fn rr_switch_quantum(self) -> u64 {
        self.rr_switch_quantum
    }

    /// Converts this plugin cursor into the host/plugin protocol shape.
    ///
    /// # Errors
    ///
    /// Returns [`PluginNvcpuFingerprintSnapshotError`] when the cursor is not
    /// valid for `vcpu_count`.
    pub const fn to_protocol_snapshot(
        self,
        vcpu_count: u32,
    ) -> Result<PluginRoundRobinCursorSnapshot, PluginNvcpuFingerprintSnapshotError> {
        PluginRoundRobinCursorSnapshot::new(
            self.current_vcpu,
            self.cursor_position,
            self.rr_switch_quantum,
            vcpu_count,
        )
    }
}

/// Plugin-side inputs required by the N-vCPU execution fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginNvcpuFingerprintInputs {
    vcpu_registers: Vec<PluginVcpuRegisterDigest>,
    rr_cursor: PluginRoundRobinCursor,
}

impl PluginNvcpuFingerprintInputs {
    /// Builds a validated N-vCPU fingerprint input set.
    ///
    /// # Errors
    ///
    /// Returns [`VcpuIntrospectionError::ZeroVcpuCount`] when no vCPU register
    /// digests were supplied, [`VcpuIntrospectionError::MismatchedVcpuSet`] when
    /// the register set is not exactly `0..N`, or another cursor validation
    /// error when the RR cursor is malformed.
    pub fn new(
        mut vcpu_registers: Vec<PluginVcpuRegisterDigest>,
        rr_cursor: PluginRoundRobinCursor,
    ) -> Result<Self, VcpuIntrospectionError> {
        if vcpu_registers.is_empty() {
            return Err(VcpuIntrospectionError::ZeroVcpuCount);
        }
        vcpu_registers.sort_by_key(PluginVcpuRegisterDigest::vcpu_id);
        for (expected, register) in vcpu_registers.iter().enumerate() {
            let expected = u32::try_from(expected).map_err(|_error| {
                VcpuIntrospectionError::VcpuCountTooLarge {
                    vcpu_count: vcpu_registers.len(),
                }
            })?;
            if register.vcpu_id() != expected {
                return Err(VcpuIntrospectionError::MismatchedVcpuSet {
                    expected_vcpu: expected,
                    observed_vcpu: register.vcpu_id(),
                });
            }
        }
        if rr_cursor.current_vcpu() >= vcpu_registers.len() as u64 {
            return Err(VcpuIntrospectionError::CurrentVcpuOutOfRange {
                current_vcpu: rr_cursor.current_vcpu(),
                vcpu_count: u32::try_from(vcpu_registers.len()).map_err(|_error| {
                    VcpuIntrospectionError::VcpuCountTooLarge {
                        vcpu_count: vcpu_registers.len(),
                    }
                })?,
            });
        }
        Ok(Self {
            vcpu_registers,
            rr_cursor,
        })
    }

    /// Returns sorted per-vCPU register digests.
    #[must_use]
    pub fn vcpu_registers(&self) -> &[PluginVcpuRegisterDigest] {
        &self.vcpu_registers
    }

    /// Returns the round-robin cursor snapshot.
    #[must_use]
    pub const fn rr_cursor(&self) -> PluginRoundRobinCursor {
        self.rr_cursor
    }

    /// Converts the plugin reader output into the validated host/plugin protocol snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`PluginNvcpuFingerprintSnapshotError`] when the plugin output is
    /// malformed or too large for the shared snapshot contract.
    pub fn to_protocol_snapshot(
        &self,
    ) -> Result<PluginNvcpuFingerprintSnapshot, PluginNvcpuFingerprintSnapshotError> {
        let vcpu_count = u32::try_from(self.vcpu_registers.len()).map_err(|_error| {
            PluginNvcpuFingerprintSnapshotError::VcpuCountTooLarge {
                vcpu_count: self.vcpu_registers.len(),
            }
        })?;
        let registers = self
            .vcpu_registers
            .iter()
            .map(PluginVcpuRegisterDigest::to_protocol_snapshot)
            .collect::<Result<Vec<_>, _>>()?;
        let cursor = self.rr_cursor.to_protocol_snapshot(vcpu_count)?;
        PluginNvcpuFingerprintSnapshot::new(registers, cursor)
    }
}

/// Required plugin-side handle for PATCH-46 introspection.
#[derive(Clone, Copy, Debug)]
pub struct PluginVcpuIntrospector {
    read_vcpu_regs: QemuReadVcpuRegsFn,
    read_rr_cursor: QemuReadRrCursorFn,
}

impl PluginVcpuIntrospector {
    /// Requires QEMU's per-vCPU register and RR-cursor exports.
    ///
    /// # Errors
    ///
    /// Returns [`VcpuIntrospectionError::CapabilityUnavailable`] when either
    /// required export was not resolved.
    pub fn require(
        read_vcpu_regs: Option<QemuReadVcpuRegsFn>,
        read_rr_cursor: Option<QemuReadRrCursorFn>,
    ) -> Result<Self, VcpuIntrospectionError> {
        let Some(read_vcpu_regs) = read_vcpu_regs else {
            return Err(VcpuIntrospectionError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL,
            });
        };
        let Some(read_rr_cursor) = read_rr_cursor else {
            return Err(VcpuIntrospectionError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_RR_CURSOR_SYMBOL,
            });
        };
        Ok(Self {
            read_vcpu_regs,
            read_rr_cursor,
        })
    }

    /// Reads all vCPU register files and the RR cursor for one fingerprint sample.
    ///
    /// # Errors
    ///
    /// Returns [`VcpuIntrospectionError`] when `vcpu_count` is zero, QEMU rejects
    /// any register/cursor read, or the returned cursor/register set is malformed.
    pub fn read_nvcpu_fingerprint_inputs(
        &self,
        vcpu_count: u32,
    ) -> Result<PluginNvcpuFingerprintInputs, VcpuIntrospectionError> {
        if vcpu_count == 0 {
            return Err(VcpuIntrospectionError::ZeroVcpuCount);
        }

        let cursor = self.read_round_robin_cursor(vcpu_count)?;
        let mut registers = Vec::with_capacity(vcpu_count as usize);
        for vcpu_id in 0..vcpu_count {
            registers.push(self.read_one_vcpu_registers(vcpu_id)?);
        }
        PluginNvcpuFingerprintInputs::new(registers, cursor)
    }

    fn read_one_vcpu_registers(
        &self,
        vcpu_id: u32,
    ) -> Result<PluginVcpuRegisterDigest, VcpuIntrospectionError> {
        let mut register_bytes = [0_u8; MAX_VCPU_REGISTER_FILE_BYTES];
        let mut register_len = 0_usize;
        let mut retired_instruction_count = 0_u64;
        let status = (self.read_vcpu_regs)(
            vcpu_id,
            register_bytes.as_mut_ptr(),
            register_bytes.len(),
            &mut register_len,
            &mut retired_instruction_count,
        );
        if status != 0 {
            return Err(VcpuIntrospectionError::RegisterReadRejected { vcpu_id, status });
        }
        if register_len > register_bytes.len() {
            return Err(VcpuIntrospectionError::RegisterFileTooLarge {
                vcpu_id,
                len: register_len,
                max: register_bytes.len(),
            });
        }
        PluginVcpuRegisterDigest::new(
            vcpu_id,
            &register_bytes[..register_len],
            retired_instruction_count,
        )
    }

    fn read_round_robin_cursor(
        &self,
        vcpu_count: u32,
    ) -> Result<PluginRoundRobinCursor, VcpuIntrospectionError> {
        let mut raw = QemuRoundRobinCursor::default();
        let status = (self.read_rr_cursor)(&mut raw);
        if status != 0 {
            return Err(VcpuIntrospectionError::CursorReadRejected { status });
        }
        PluginRoundRobinCursor::new(
            raw.current_vcpu,
            raw.cursor_position,
            raw.rr_switch_quantum,
            vcpu_count,
        )
    }
}

/// Error returned by per-vCPU fingerprint introspection.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum VcpuIntrospectionError {
    /// A required QEMU plugin symbol is unavailable.
    #[error("required vCPU introspection capability `{symbol}` is unavailable")]
    CapabilityUnavailable {
        /// The missing QEMU plugin symbol.
        symbol: &'static str,
    },
    /// The configured vCPU count was zero.
    #[error("vCPU introspection requires at least one vCPU")]
    ZeroVcpuCount,
    /// The vCPU count could not be represented in the plugin fingerprint model.
    #[error("vCPU count {vcpu_count} is too large for fingerprint introspection")]
    VcpuCountTooLarge {
        /// Rejected vCPU count.
        vcpu_count: usize,
    },
    /// QEMU rejected a register-file read.
    #[error("QEMU rejected register-file read for vCPU {vcpu_id} with status {status}")]
    RegisterReadRejected {
        /// vCPU whose registers were requested.
        vcpu_id: u32,
        /// QEMU error status.
        status: c_int,
    },
    /// QEMU rejected a cursor read.
    #[error("QEMU rejected round-robin cursor read with status {status}")]
    CursorReadRejected {
        /// QEMU error status.
        status: c_int,
    },
    /// QEMU reported no register bytes for a vCPU.
    #[error("QEMU returned an empty register file for vCPU {vcpu_id}")]
    EmptyRegisterFile {
        /// vCPU whose register file was empty.
        vcpu_id: u32,
    },
    /// QEMU reported more register bytes than the plugin accepts.
    #[error("QEMU returned {len} register bytes for vCPU {vcpu_id}, maximum is {max}")]
    RegisterFileTooLarge {
        /// vCPU whose register file was too large.
        vcpu_id: u32,
        /// Reported register byte count.
        len: usize,
        /// Maximum accepted register byte count.
        max: usize,
    },
    /// The cursor named a current vCPU outside the sampled vCPU set.
    #[error("RR cursor current vCPU {current_vcpu} is outside configured count {vcpu_count}")]
    CurrentVcpuOutOfRange {
        /// Rejected current vCPU.
        current_vcpu: u64,
        /// Configured vCPU count.
        vcpu_count: u32,
    },
    /// The cursor reported a zero RR quantum.
    #[error("RR cursor reported zero rr_switch_quantum")]
    ZeroSwitchQuantum,
    /// The cursor position exceeded the pinned quantum.
    #[error("RR cursor position {cursor_position} reaches quantum {rr_switch_quantum}")]
    CursorPastQuantum {
        /// Reported cursor position.
        cursor_position: u64,
        /// Reported pinned RR switch quantum.
        rr_switch_quantum: u64,
    },
    /// The register snapshot did not name the canonical `0..N` vCPU set.
    #[error("register snapshot expected vCPU {expected_vcpu}, observed vCPU {observed_vcpu}")]
    MismatchedVcpuSet {
        /// Expected vCPU id at this sorted position.
        expected_vcpu: u32,
        /// Observed vCPU id at this sorted position.
        observed_vcpu: u32,
    },
}

/// Computes the stable 256-bit digest for one canonical register-file byte stream.
#[must_use]
pub fn digest_register_file(
    vcpu_id: u32,
    register_file: &[u8],
) -> [u8; PLUGIN_REGISTER_DIGEST_BYTES] {
    let mut digest = [0_u8; PLUGIN_REGISTER_DIGEST_BYTES];
    for lane in 0..4 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ lane as u64;
        hash = fnv1a_u64(hash, u64::from(vcpu_id));
        hash = fnv1a_u64(hash, register_file.len() as u64);
        for byte in register_file {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        digest[lane * 8..(lane + 1) * 8].copy_from_slice(&hash.to_le_bytes());
    }
    digest
}

const fn fnv1a_u64(mut hash: u64, value: u64) -> u64 {
    let bytes = value.to_le_bytes();
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;

    use crate::RoundRobinConfig;

    thread_local! {
        static READ_LOG: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    }

    fn reset_log() {
        READ_LOG.with(|log| log.borrow_mut().clear());
    }

    fn read_log() -> Vec<u32> {
        READ_LOG.with(|log| log.borrow().clone())
    }

    extern "C" fn read_test_registers(
        vcpu_id: u32,
        out_register_bytes: *mut u8,
        out_register_capacity: usize,
        out_register_len: *mut usize,
        out_retired_instruction_count: *mut u64,
    ) -> c_int {
        if vcpu_id >= 2 || out_register_capacity < 3 {
            return -2;
        }
        READ_LOG.with(|log| log.borrow_mut().push(vcpu_id));
        // SAFETY: tests pass pointers to live stack variables and a buffer with
        // at least three bytes when this helper returns success.
        unsafe {
            *out_register_bytes.add(0) = vcpu_id as u8;
            *out_register_bytes.add(1) = 0xa0 + vcpu_id as u8;
            *out_register_bytes.add(2) = 0xf0;
            *out_register_len = 3;
            *out_retired_instruction_count = 100 + u64::from(vcpu_id);
        }
        0
    }

    extern "C" fn read_empty_registers(
        _vcpu_id: u32,
        _out_register_bytes: *mut u8,
        _out_register_capacity: usize,
        out_register_len: *mut usize,
        out_retired_instruction_count: *mut u64,
    ) -> c_int {
        // SAFETY: tests pass pointers to live stack variables.
        unsafe {
            *out_register_len = 0;
            *out_retired_instruction_count = 0;
        }
        0
    }

    extern "C" fn read_test_cursor(out_cursor: *mut QemuRoundRobinCursor) -> c_int {
        // SAFETY: tests pass a pointer to a live stack cursor.
        unsafe {
            *out_cursor = QemuRoundRobinCursor {
                current_vcpu: 1,
                cursor_position: 3,
                rr_switch_quantum: 8,
            };
        }
        0
    }

    extern "C" fn read_bad_cursor(out_cursor: *mut QemuRoundRobinCursor) -> c_int {
        // SAFETY: tests pass a pointer to a live stack cursor.
        unsafe {
            *out_cursor = QemuRoundRobinCursor {
                current_vcpu: 1,
                cursor_position: 8,
                rr_switch_quantum: 8,
            };
        }
        0
    }

    extern "C" fn reject_cursor(_out_cursor: *mut QemuRoundRobinCursor) -> c_int {
        -7
    }

    #[test]
    fn vcpu_introspection_requires_register_and_cursor_capabilities() {
        assert_eq!(
            PluginVcpuIntrospector::require(None, Some(read_test_cursor)).map(|_reader| ()),
            Err(VcpuIntrospectionError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL,
            })
        );
        assert_eq!(
            PluginVcpuIntrospector::require(Some(read_test_registers), None).map(|_reader| ()),
            Err(VcpuIntrospectionError::CapabilityUnavailable {
                symbol: QEMU_PLUGIN_RR_CURSOR_SYMBOL,
            })
        );
    }

    #[test]
    fn vcpu_introspection_reads_all_vcpu_registers_and_rr_cursor() {
        reset_log();
        let introspector =
            PluginVcpuIntrospector::require(Some(read_test_registers), Some(read_test_cursor))
                .unwrap_or_else(|error| panic!("introspector should validate: {error}"));

        let inputs = introspector
            .read_nvcpu_fingerprint_inputs(2)
            .unwrap_or_else(|error| panic!("fingerprint inputs should read: {error}"));

        assert_eq!(read_log(), vec![0, 1]);
        assert_eq!(inputs.vcpu_registers().len(), 2);
        assert_eq!(inputs.vcpu_registers()[0].vcpu_id(), 0);
        assert_eq!(inputs.vcpu_registers()[1].vcpu_id(), 1);
        assert_eq!(inputs.vcpu_registers()[1].retired_instruction_count(), 101);
        assert_eq!(inputs.rr_cursor().current_vcpu(), 1);
        assert_eq!(inputs.rr_cursor().cursor_position(), 3);
        assert_eq!(inputs.rr_cursor().quantum_remaining(), 5);
        assert_eq!(inputs.rr_cursor().rr_switch_quantum(), 8);
    }

    #[test]
    fn vcpu_introspection_converts_reader_output_to_protocol_snapshot() {
        reset_log();
        let introspector =
            PluginVcpuIntrospector::require(Some(read_test_registers), Some(read_test_cursor))
                .unwrap_or_else(|error| panic!("introspector should validate: {error}"));

        let inputs = introspector
            .read_nvcpu_fingerprint_inputs(2)
            .unwrap_or_else(|error| panic!("fingerprint inputs should read: {error}"));
        let snapshot = inputs
            .to_protocol_snapshot()
            .unwrap_or_else(|error| panic!("protocol snapshot should validate: {error}"));

        assert_eq!(read_log(), vec![0, 1]);
        assert_eq!(snapshot.vcpu_registers().len(), 2);
        assert_eq!(snapshot.vcpu_registers()[0].vcpu_id(), 0);
        assert_eq!(
            snapshot.vcpu_registers()[1].register_digest(),
            inputs.vcpu_registers()[1].register_digest()
        );
        assert_eq!(snapshot.vcpu_registers()[1].register_file_bytes(), 3);
        assert_eq!(
            snapshot.vcpu_registers()[1].retired_instruction_count(),
            101
        );
        assert_eq!(snapshot.rr_cursor().current_vcpu(), 1);
        assert_eq!(snapshot.rr_cursor().position_in_quantum(), 3);
        assert_eq!(snapshot.rr_cursor().rr_switch_quantum(), 8);
    }

    #[test]
    fn vcpu_introspection_rejects_bad_cursor_before_register_reads() {
        reset_log();
        let bad_cursor =
            PluginVcpuIntrospector::require(Some(read_test_registers), Some(read_bad_cursor))
                .unwrap_or_else(|error| panic!("introspector should validate: {error}"));
        assert_eq!(
            bad_cursor.read_nvcpu_fingerprint_inputs(2),
            Err(VcpuIntrospectionError::CursorPastQuantum {
                cursor_position: 8,
                rr_switch_quantum: 8,
            })
        );
        assert_eq!(read_log(), Vec::<u32>::new());

        let rejected_cursor =
            PluginVcpuIntrospector::require(Some(read_test_registers), Some(reject_cursor))
                .unwrap_or_else(|error| panic!("introspector should validate: {error}"));
        assert_eq!(
            rejected_cursor.read_nvcpu_fingerprint_inputs(2),
            Err(VcpuIntrospectionError::CursorReadRejected { status: -7 })
        );
        assert_eq!(read_log(), Vec::<u32>::new());

        let empty_registers =
            PluginVcpuIntrospector::require(Some(read_empty_registers), Some(read_test_cursor))
                .unwrap_or_else(|error| panic!("introspector should validate: {error}"));
        assert_eq!(
            empty_registers.read_nvcpu_fingerprint_inputs(2),
            Err(VcpuIntrospectionError::EmptyRegisterFile { vcpu_id: 0 })
        );
    }

    #[test]
    fn vcpu_introspection_register_digest_is_stable_and_vcpu_qualified() {
        let first = digest_register_file(0, &[1, 2, 3]);
        let second = digest_register_file(0, &[1, 2, 3]);
        let different_vcpu = digest_register_file(1, &[1, 2, 3]);
        let different_bytes = digest_register_file(0, &[1, 2, 4]);

        assert_eq!(first, second);
        assert_ne!(first, different_vcpu);
        assert_ne!(first, different_bytes);
        assert_eq!(first.len(), PLUGIN_REGISTER_DIGEST_BYTES);
    }

    #[test]
    fn vcpu_introspection_cursor_can_be_derived_from_local_round_robin_state() {
        let config = RoundRobinConfig::new(2, 8)
            .unwrap_or_else(|error| panic!("round-robin config should validate: {error}"));
        let mut state = RoundRobinRunState::new(config, 0)
            .unwrap_or_else(|error| panic!("round-robin state should validate: {error}"));
        state
            .retire(0, 3)
            .unwrap_or_else(|error| panic!("retirement should validate: {error}"));

        let cursor = PluginRoundRobinCursor::from_run_state(state);
        assert_eq!(cursor.current_vcpu(), 0);
        assert_eq!(cursor.cursor_position(), 3);
        assert_eq!(cursor.quantum_remaining(), 5);
        assert_eq!(cursor.rr_switch_quantum(), 8);
    }
}

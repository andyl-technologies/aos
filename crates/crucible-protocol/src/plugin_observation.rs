//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Validated plugin observations for registers, scheduling and coverage.
//!
//! This module owns portable register and round-robin cursor snapshots, basic
//! block coverage observations, and the coherent per-vCPU fingerprint inventory.
//! Validation rejects incomplete register sets and impossible scheduler cursors.

use thiserror::Error;

/// Byte length of plugin-to-host per-vCPU register digests.
pub const PLUGIN_NVCPU_REGISTER_DIGEST_BYTES: usize = 32;

/// Validated per-vCPU register material exported by the QEMU plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginVcpuRegisterSnapshot {
    vcpu_id: u32,
    register_digest: [u8; PLUGIN_NVCPU_REGISTER_DIGEST_BYTES],
    register_file_bytes: usize,
    retired_instruction_count: u64,
}

impl PluginVcpuRegisterSnapshot {
    /// Builds one plugin register snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`PluginNvcpuFingerprintSnapshotError::EmptyRegisterFile`] when
    /// `register_file_bytes` is zero.
    pub const fn new(
        vcpu_id: u32,
        register_digest: [u8; PLUGIN_NVCPU_REGISTER_DIGEST_BYTES],
        register_file_bytes: usize,
        retired_instruction_count: u64,
    ) -> Result<Self, PluginNvcpuFingerprintSnapshotError> {
        if register_file_bytes == 0 {
            return Err(PluginNvcpuFingerprintSnapshotError::EmptyRegisterFile { vcpu_id });
        }
        Ok(Self {
            vcpu_id,
            register_digest,
            register_file_bytes,
            retired_instruction_count,
        })
    }

    /// Returns the vCPU identifier.
    #[must_use]
    pub const fn vcpu_id(&self) -> u32 {
        self.vcpu_id
    }

    /// Returns the fixed-width register digest.
    #[must_use]
    pub const fn register_digest(&self) -> &[u8; PLUGIN_NVCPU_REGISTER_DIGEST_BYTES] {
        &self.register_digest
    }

    /// Returns the number of canonical register bytes read by the plugin.
    #[must_use]
    pub const fn register_file_bytes(&self) -> usize {
        self.register_file_bytes
    }

    /// Returns the adapter-provided retired-instruction stamp for the registers.
    #[must_use]
    pub const fn retired_instruction_count(&self) -> u64 {
        self.retired_instruction_count
    }
}

/// Validated round-robin cursor material exported by the QEMU plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginRoundRobinCursorSnapshot {
    current_vcpu: u64,
    position_in_quantum: u64,
    rr_switch_quantum: u64,
}

impl PluginRoundRobinCursorSnapshot {
    /// Builds one plugin round-robin cursor snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`PluginNvcpuFingerprintSnapshotError`] when `vcpu_count` is
    /// zero, `current_vcpu` is outside `0..vcpu_count`,
    /// `rr_switch_quantum` is zero, or `position_in_quantum` is outside the
    /// current quantum.
    pub const fn new(
        current_vcpu: u64,
        position_in_quantum: u64,
        rr_switch_quantum: u64,
        vcpu_count: u32,
    ) -> Result<Self, PluginNvcpuFingerprintSnapshotError> {
        if vcpu_count == 0 {
            return Err(PluginNvcpuFingerprintSnapshotError::ZeroVcpuCount);
        }
        if current_vcpu >= vcpu_count as u64 {
            return Err(PluginNvcpuFingerprintSnapshotError::CurrentVcpuOutOfRange {
                current_vcpu,
                vcpu_count,
            });
        }
        if rr_switch_quantum == 0 {
            return Err(PluginNvcpuFingerprintSnapshotError::ZeroSwitchQuantum);
        }
        if position_in_quantum >= rr_switch_quantum {
            return Err(PluginNvcpuFingerprintSnapshotError::CursorPastQuantum {
                position_in_quantum,
                rr_switch_quantum,
            });
        }
        Ok(Self {
            current_vcpu,
            position_in_quantum,
            rr_switch_quantum,
        })
    }

    /// Returns the currently running vCPU.
    #[must_use]
    pub const fn current_vcpu(self) -> u64 {
        self.current_vcpu
    }

    /// Returns the node-icount position inside the current quantum.
    #[must_use]
    pub const fn position_in_quantum(self) -> u64 {
        self.position_in_quantum
    }

    /// Returns the pinned round-robin switch quantum.
    #[must_use]
    pub const fn rr_switch_quantum(self) -> u64 {
        self.rr_switch_quantum
    }
}

/// One plugin-to-host black-box basic-block coverage observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginBasicBlockCoverageObservation {
    current_icount: u64,
    vcpu_index: u32,
    guest_pc: u64,
    block_len: u32,
    map_index: u64,
    was_new: bool,
}

impl PluginBasicBlockCoverageObservation {
    /// Builds one validated plugin basic-block coverage observation.
    ///
    /// # Errors
    ///
    /// Returns [`PluginBasicBlockCoverageObservationError::InvalidBlockLength`]
    /// when QEMU reports a zero-length translated block.
    pub const fn new(
        current_icount: u64,
        vcpu_index: u32,
        guest_pc: u64,
        block_len: u32,
        map_index: u64,
        was_new: bool,
    ) -> Result<Self, PluginBasicBlockCoverageObservationError> {
        if block_len == 0 {
            return Err(PluginBasicBlockCoverageObservationError::InvalidBlockLength { block_len });
        }
        Ok(Self {
            current_icount,
            vcpu_index,
            guest_pc,
            block_len,
            map_index,
            was_new,
        })
    }

    /// Returns the aggregate instruction count at which QEMU reported the block.
    #[must_use]
    pub const fn current_icount(self) -> u64 {
        self.current_icount
    }

    /// Returns the vCPU that executed the translated block.
    #[must_use]
    pub const fn vcpu_index(self) -> u32 {
        self.vcpu_index
    }

    /// Returns the guest program counter for the translated block.
    #[must_use]
    pub const fn guest_pc(self) -> u64 {
        self.guest_pc
    }

    /// Returns the translated block length supplied by QEMU.
    #[must_use]
    pub const fn block_len(self) -> u32 {
        self.block_len
    }

    /// Returns the plugin coverage-map index touched by this block.
    #[must_use]
    pub const fn map_index(self) -> u64 {
        self.map_index
    }

    /// Returns whether this block touched a previously empty coverage-map entry.
    #[must_use]
    pub const fn was_new(self) -> bool {
        self.was_new
    }
}

/// An invalid plugin basic-block coverage observation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginBasicBlockCoverageObservationError {
    /// QEMU reported an impossible basic-block length.
    #[error("plugin basic-block coverage length {block_len} is invalid")]
    InvalidBlockLength {
        /// Rejected block length.
        block_len: u32,
    },
}

/// Validated plugin-to-host N-vCPU fingerprint snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginNvcpuFingerprintSnapshot {
    vcpu_registers: Vec<PluginVcpuRegisterSnapshot>,
    rr_cursor: PluginRoundRobinCursorSnapshot,
}

impl PluginNvcpuFingerprintSnapshot {
    /// Builds one validated plugin-to-host fingerprint snapshot.
    ///
    /// Register snapshots are sorted into vCPU-id order and must cover exactly
    /// `0..N`.
    ///
    /// # Errors
    ///
    /// Returns [`PluginNvcpuFingerprintSnapshotError`] when the register set is
    /// empty, non-contiguous, too large for the wire contract, or inconsistent
    /// with the round-robin cursor.
    pub fn new(
        mut vcpu_registers: Vec<PluginVcpuRegisterSnapshot>,
        rr_cursor: PluginRoundRobinCursorSnapshot,
    ) -> Result<Self, PluginNvcpuFingerprintSnapshotError> {
        if vcpu_registers.is_empty() {
            return Err(PluginNvcpuFingerprintSnapshotError::ZeroVcpuCount);
        }
        vcpu_registers.sort_by_key(PluginVcpuRegisterSnapshot::vcpu_id);
        for (expected, register) in vcpu_registers.iter().enumerate() {
            let expected = u32::try_from(expected).map_err(|_error| {
                PluginNvcpuFingerprintSnapshotError::VcpuCountTooLarge {
                    vcpu_count: vcpu_registers.len(),
                }
            })?;
            if register.vcpu_id() != expected {
                return Err(PluginNvcpuFingerprintSnapshotError::MismatchedVcpuSet {
                    expected_vcpu: expected,
                    observed_vcpu: register.vcpu_id(),
                });
            }
        }
        if rr_cursor.current_vcpu() >= vcpu_registers.len() as u64 {
            return Err(PluginNvcpuFingerprintSnapshotError::CurrentVcpuOutOfRange {
                current_vcpu: rr_cursor.current_vcpu(),
                vcpu_count: u32::try_from(vcpu_registers.len()).map_err(|_error| {
                    PluginNvcpuFingerprintSnapshotError::VcpuCountTooLarge {
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

    /// Returns sorted per-vCPU register snapshots.
    #[must_use]
    pub fn vcpu_registers(&self) -> &[PluginVcpuRegisterSnapshot] {
        &self.vcpu_registers
    }

    /// Returns the sampled round-robin cursor.
    #[must_use]
    pub const fn rr_cursor(&self) -> PluginRoundRobinCursorSnapshot {
        self.rr_cursor
    }
}

/// Error returned for malformed plugin N-vCPU fingerprint snapshots.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PluginNvcpuFingerprintSnapshotError {
    /// No vCPUs were present in the snapshot.
    #[error("plugin N-vCPU fingerprint snapshot must include at least one vCPU")]
    ZeroVcpuCount,
    /// The snapshot contains more vCPUs than the protocol can index.
    #[error("plugin N-vCPU fingerprint snapshot vCPU count {vcpu_count} is too large")]
    VcpuCountTooLarge {
        /// Number of vCPUs in the snapshot.
        vcpu_count: usize,
    },
    /// One register snapshot had no architectural register bytes.
    #[error("plugin vCPU {vcpu_id} register snapshot is empty")]
    EmptyRegisterFile {
        /// vCPU whose register snapshot was empty.
        vcpu_id: u32,
    },
    /// The current RR cursor vCPU was outside the snapshot's vCPU set.
    #[error("plugin RR current vCPU {current_vcpu} is outside vCPU count {vcpu_count}")]
    CurrentVcpuOutOfRange {
        /// Current vCPU reported by the plugin.
        current_vcpu: u64,
        /// Number of vCPUs in the snapshot.
        vcpu_count: u32,
    },
    /// The pinned RR switch quantum was zero.
    #[error("plugin RR switch quantum must be non-zero")]
    ZeroSwitchQuantum,
    /// The RR cursor position reached or exceeded the pinned quantum.
    #[error(
        "plugin RR cursor position {position_in_quantum} is outside quantum {rr_switch_quantum}"
    )]
    CursorPastQuantum {
        /// Position inside the current quantum.
        position_in_quantum: u64,
        /// Pinned RR switch quantum.
        rr_switch_quantum: u64,
    },
    /// The per-vCPU register set was not exactly `0..N`.
    #[error("plugin register set expected vCPU {expected_vcpu}, observed {observed_vcpu}")]
    MismatchedVcpuSet {
        /// Expected vCPU at this sorted register position.
        expected_vcpu: u32,
        /// Observed vCPU at this sorted register position.
        observed_vcpu: u32,
    },
}

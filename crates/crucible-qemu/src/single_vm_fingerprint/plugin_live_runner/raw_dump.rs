//! Host-side parsing and comparison of plugin terminal raw-state artifacts.

use std::fs;
use std::path::{Path, PathBuf};

use crate::single_vm_fingerprint::{
    SingleVmFingerprintMemoryRegionState, SingleVmFingerprintRunStateDump,
    SingleVmFingerprintVcpuState,
};

use super::{PluginFingerprintRunnerError, RUNNER_NODE};

const DUMP_MAGIC: &[u8; 8] = b"CRUCDMP1";
const ERROR_MAGIC: &[u8; 8] = b"CRUCERR1";

#[derive(Clone, Debug)]
pub(super) struct RawStateArtifact {
    pub(super) icount: u64,
    registers: Vec<Vec<u8>>,
    ram: Vec<RawRamRegion>,
    device_state: Vec<u8>,
}

#[derive(Clone, Debug)]
struct RawRamRegion {
    start: u64,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(super) struct PreparedStateDumpPair {
    pub(super) target_icount: u64,
    pub(super) first: SingleVmFingerprintRunStateDump,
    pub(super) second: SingleVmFingerprintRunStateDump,
}

pub(super) fn read_raw_state_artifact(
    path: &Path,
) -> Result<RawStateArtifact, PluginFingerprintRunnerError> {
    let bytes = fs::read(path).map_err(|source| PluginFingerprintRunnerError::ReadStateDump {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.starts_with(ERROR_MAGIC) {
        return Err(PluginFingerprintRunnerError::StateDumpExport {
            diagnostic: String::from_utf8_lossy(&bytes[ERROR_MAGIC.len()..]).into_owned(),
        });
    }
    let mut input = Input::new(&bytes, path);
    input.consume_expected(DUMP_MAGIC)?;
    let icount = input.u64()?;
    let vcpu_count = input.u32()?;
    let mut registers = Vec::with_capacity(vcpu_count as usize);
    for expected_vcpu in 0..vcpu_count {
        let vcpu_id = input.u32()?;
        if vcpu_id != expected_vcpu {
            return Err(input.invalid("vCPU identifiers are not canonical 0..N"));
        }
        registers.push(input.bytes()?);
    }
    let ram_count = input.u64()?;
    let ram_count = usize::try_from(ram_count)
        .map_err(|_error| input.invalid("RAM region count exceeds host addressability"))?;
    let mut ram = Vec::with_capacity(ram_count);
    for _ in 0..ram_count {
        let start = input.u64()?;
        let length = input.u64()?;
        let bytes = input.fixed_bytes(length)?;
        ram.push(RawRamRegion { start, bytes });
    }
    let device_state = input.bytes()?;
    if !input.remaining().is_empty() {
        return Err(input.invalid("terminal state dump has trailing bytes"));
    }
    Ok(RawStateArtifact {
        icount,
        registers,
        ram,
        device_state,
    })
}

pub(super) fn build_state_dump_pair(
    target_icount: u64,
    first: RawStateArtifact,
    second: RawStateArtifact,
) -> Result<PreparedStateDumpPair, PluginFingerprintRunnerError> {
    if first.icount != target_icount || second.icount != target_icount {
        return Err(PluginFingerprintRunnerError::StateDumpTargetMismatch {
            target_icount,
            first_icount: first.icount,
            second_icount: second.icount,
        });
    }
    if first.registers.len() != second.registers.len() || first.ram.len() != second.ram.len() {
        return Err(PluginFingerprintRunnerError::StateDumpTopologyMismatch);
    }
    let first_registers = vcpu_states(&first.registers)?;
    let second_registers = vcpu_states(&second.registers)?;
    let (first_memory, second_memory) = differing_memory(&first.ram, &second.ram)?;
    let first_state = SingleVmFingerprintRunStateDump::new(
        RUNNER_NODE,
        target_icount,
        first_registers,
        first_memory,
        first.device_state,
        0,
        Vec::new(),
    )
    .map_err(PluginFingerprintRunnerError::BuildStateDump)?;
    let second_state = SingleVmFingerprintRunStateDump::new(
        RUNNER_NODE,
        target_icount,
        second_registers,
        second_memory,
        second.device_state,
        0,
        Vec::new(),
    )
    .map_err(PluginFingerprintRunnerError::BuildStateDump)?;
    Ok(PreparedStateDumpPair {
        target_icount,
        first: first_state,
        second: second_state,
    })
}

fn vcpu_states(
    registers: &[Vec<u8>],
) -> Result<Vec<SingleVmFingerprintVcpuState>, PluginFingerprintRunnerError> {
    registers
        .iter()
        .enumerate()
        .map(|(vcpu_id, bytes)| {
            SingleVmFingerprintVcpuState::new(vcpu_id as u64, bytes.clone())
                .map_err(PluginFingerprintRunnerError::BuildStateDump)
        })
        .collect()
}

fn differing_memory(
    first: &[RawRamRegion],
    second: &[RawRamRegion],
) -> Result<
    (
        Vec<SingleVmFingerprintMemoryRegionState>,
        Vec<SingleVmFingerprintMemoryRegionState>,
    ),
    PluginFingerprintRunnerError,
> {
    let mut first_diffs = Vec::new();
    let mut second_diffs = Vec::new();
    for (first_region, second_region) in first.iter().zip(second) {
        if first_region.start != second_region.start
            || first_region.bytes.len() != second_region.bytes.len()
        {
            return Err(PluginFingerprintRunnerError::StateDumpTopologyMismatch);
        }
        let mut cursor = 0_usize;
        while cursor < first_region.bytes.len() {
            if first_region.bytes[cursor] == second_region.bytes[cursor] {
                cursor += 1;
                continue;
            }
            let begin = cursor;
            while cursor < first_region.bytes.len()
                && first_region.bytes[cursor] != second_region.bytes[cursor]
            {
                cursor += 1;
            }
            let start = first_region
                .start
                .checked_add(begin as u64)
                .ok_or(PluginFingerprintRunnerError::StateDumpTopologyMismatch)?;
            first_diffs.push(
                SingleVmFingerprintMemoryRegionState::new(
                    start,
                    first_region.bytes[begin..cursor].to_vec(),
                )
                .map_err(PluginFingerprintRunnerError::BuildStateDump)?,
            );
            second_diffs.push(
                SingleVmFingerprintMemoryRegionState::new(
                    start,
                    second_region.bytes[begin..cursor].to_vec(),
                )
                .map_err(PluginFingerprintRunnerError::BuildStateDump)?,
            );
        }
    }
    Ok((first_diffs, second_diffs))
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
    path: PathBuf,
}

impl<'a> Input<'a> {
    fn new(bytes: &'a [u8], path: &Path) -> Self {
        Self {
            bytes,
            offset: 0,
            path: path.to_path_buf(),
        }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn consume_expected(&mut self, expected: &[u8]) -> Result<(), PluginFingerprintRunnerError> {
        let actual = self.take(expected.len())?;
        if actual == expected {
            Ok(())
        } else {
            Err(self.invalid("terminal state dump magic is invalid"))
        }
    }

    fn u32(&mut self) -> Result<u32, PluginFingerprintRunnerError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_error| self.invalid("truncated u32"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, PluginFingerprintRunnerError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_error| self.invalid("truncated u64"))?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, PluginFingerprintRunnerError> {
        let length = self.u64()?;
        self.fixed_bytes(length)
    }

    fn fixed_bytes(&mut self, length: u64) -> Result<Vec<u8>, PluginFingerprintRunnerError> {
        let length = usize::try_from(length)
            .map_err(|_error| self.invalid("byte range exceeds host addressability"))?;
        Ok(self.take(length)?.to_vec())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PluginFingerprintRunnerError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| self.invalid("terminal state dump offset overflow"))?;
        if end > self.bytes.len() {
            return Err(self.invalid("terminal state dump is truncated"));
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn invalid(&self, reason: &'static str) -> PluginFingerprintRunnerError {
        PluginFingerprintRunnerError::InvalidStateDump {
            path: self.path.clone(),
            reason,
        }
    }
}

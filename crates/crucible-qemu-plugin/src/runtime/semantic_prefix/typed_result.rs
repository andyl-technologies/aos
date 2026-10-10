//! Historical typed native prefix conversion, separate from initial Result256.
//!
//! CPU retirements and timer callbacks remain independent copied counts. The
//! consumer checks exact source handles and prior history before publication;
//! no raw-count projection supplies a Position or callback ancestry.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::{NativeEffectPosition, SourcePrefixEffectCut, SourcePrefixRootSeal};
use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    NativeCommandError, NativeEffectProgressStatus, NativePrefixEvaluationKind,
    NativePrefixProgress,
};
use std::ffi::{c_int, c_void};

#[derive(Default)]
#[repr(C)]
pub(super) struct NativeResult {
    version: u32,
    size: u32,
    scope: [u8; 32],
    preparation: [u8; 32],
    grant: [u8; 32],
    command: [u8; 32],
    sequence: u64,
    cut_id: u64,
    previous_cut_id: u64,
    acknowledgement_sequence: u64,
    raw_before: u64,
    raw_after: u64,
    evaluated: NativeEffectPosition,
    evaluation_kind: u32,
    parent_kind: u32,
    evaluation_id: u64,
    evaluation_generation: u64,
    parent_id: u64,
    parent_generation: u64,
    resulting: NativeEffectPosition,
    cpu_retirements: u64,
    timer_callbacks: u64,
    cumulative_cpu_retirements: u64,
    cumulative_timer_callbacks: u64,
    status: u32,
    flags: u32,
    end_result: i32,
    reserved: u32,
}

pub(super) type QueryResult = extern "C" fn(
    *const SourcePrefixRootSeal,
    *mut c_void,
    *const SourcePrefixEffectCut,
    *mut NativeResult,
) -> c_int;

impl NativeResult {
    pub(super) fn portable(self) -> Result<NativePrefixProgress, NativeCommandError> {
        if self.version != 2 || self.size != 320 || self.flags != 0 || self.reserved != 0 {
            return Err(NativeCommandError::Conflict);
        }
        let status = match self.status {
            1 => NativeEffectProgressStatus::PartialPrefix,
            2 => NativeEffectProgressStatus::Completed,
            3 => NativeEffectProgressStatus::EffectsUnknown,
            _ => return Err(NativeCommandError::Conflict),
        };
        let evaluation_kind = kind(self.evaluation_kind)?;
        let parent_kind = if self.parent_kind == 0 {
            None
        } else {
            Some(kind(self.parent_kind)?)
        };
        Ok(NativePrefixProgress {
            scope: self.scope,
            prefix_preparation: self.preparation,
            grant_digest: self.grant,
            command_digest: self.command,
            sequence: U64::new(self.sequence),
            cut_id: U64::new(self.cut_id),
            previous_cut_id: U64::new(self.previous_cut_id),
            acknowledgement_sequence: U64::new(self.acknowledgement_sequence),
            raw_before: U64::new(self.raw_before),
            raw_after: U64::new(self.raw_after),
            evaluated: super::result::position(self.evaluated)?,
            evaluation_kind,
            parent_kind,
            evaluation_id: U64::new(self.evaluation_id),
            evaluation_generation: U64::new(self.evaluation_generation),
            parent_id: U64::new(self.parent_id),
            parent_generation: U64::new(self.parent_generation),
            resulting: super::result::position(self.resulting)?,
            cpu_retirements: U64::new(self.cpu_retirements),
            timer_callbacks: U64::new(self.timer_callbacks),
            cumulative_cpu_retirements: U64::new(self.cumulative_cpu_retirements),
            cumulative_timer_callbacks: U64::new(self.cumulative_timer_callbacks),
            status,
            end_result: self.end_result,
        })
    }
}

fn kind(kind: u32) -> Result<NativePrefixEvaluationKind, NativeCommandError> {
    match kind {
        1 => Ok(NativePrefixEvaluationKind::CpuService),
        2 => Ok(NativePrefixEvaluationKind::TimerCallback),
        _ => Err(NativeCommandError::Conflict),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn typed_native_result_matches_distinct_counts_and_ancestry_offsets() {
        assert_eq!(size_of::<NativeResult>(), 320);
        assert_eq!(offset_of!(NativeResult, previous_cut_id), 152);
        assert_eq!(offset_of!(NativeResult, evaluated), 184);
        assert_eq!(offset_of!(NativeResult, evaluation_kind), 208);
        assert_eq!(offset_of!(NativeResult, evaluation_id), 216);
        assert_eq!(offset_of!(NativeResult, resulting), 248);
        assert_eq!(offset_of!(NativeResult, cpu_retirements), 272);
        assert_eq!(offset_of!(NativeResult, timer_callbacks), 280);
        assert_eq!(offset_of!(NativeResult, status), 304);
        assert_eq!(offset_of!(NativeResult, end_result), 312);
    }
}

//! Immutable native original-result recovery by the actual sole reader.
//!
//! Source validates its exact retained root/epoch/cut and original reader
//! lifetime before copying historical scalars. This path samples no stop and
//! never invokes an evaluation or releases original custody.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::{NativeEffectPosition, SemanticEffectOwner, SourceEffectCut, SourceRootSeal};
use crucible_node_contract::{Phase, Position, U64};
use crucible_protocol::node_control::{
    NativeCommandError, NativeEffectProgress, NativeEffectProgressStatus, NativeFrame,
};
use std::ffi::{c_int, c_void};

use crate::native_node_control::administrative_inbox::NativeAdministrativeInboxError;

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
    raw_before: u64,
    raw_after: u64,
    evaluated: NativeEffectPosition,
    evaluation_id: u64,
    evaluation_generation: u64,
    resulting: NativeEffectPosition,
    returned_service_count: u64,
    status: u32,
    flags: u32,
    end_result: i32,
    reserved: u32,
}

pub(super) type QueryResult = extern "C" fn(
    *const SourceRootSeal,
    *mut c_void,
    *const SourceEffectCut,
    *mut NativeResult,
) -> c_int;

impl NativeResult {
    fn portable(self) -> Result<NativeEffectProgress, NativeCommandError> {
        if self.version != 1 || self.size != 256 || self.flags != 0 || self.reserved != 0 {
            return Err(NativeCommandError::Conflict);
        }
        let status = match self.status {
            1 => NativeEffectProgressStatus::PartialPrefix,
            2 => NativeEffectProgressStatus::Completed,
            3 => NativeEffectProgressStatus::EffectsUnknown,
            _ => return Err(NativeCommandError::Conflict),
        };
        Ok(NativeEffectProgress {
            scope: self.scope,
            effect_preparation: self.preparation,
            grant_digest: self.grant,
            command_digest: self.command,
            sequence: U64::new(self.sequence),
            cut_id: U64::new(self.cut_id),
            raw_before: U64::new(self.raw_before),
            raw_after: U64::new(self.raw_after),
            evaluated: position(self.evaluated)?,
            evaluation_id: U64::new(self.evaluation_id),
            evaluation_generation: U64::new(self.evaluation_generation),
            resulting: position(self.resulting)?,
            returned_service_count: U64::new(self.returned_service_count),
            status,
            end_result: self.end_result,
        })
    }
}

impl SemanticEffectOwner {
    /// Recovers only the exact original source result under the actual reader identity.
    ///
    /// # Errors
    /// Refuses source contradictions, changed cached result or reply custody.
    pub(crate) fn recover_original_result(&self) -> Result<(), NativeCommandError> {
        if self.process_id != std::process::id() {
            return Err(NativeCommandError::Conflict);
        }
        let control =
            crate::native_node_control::registered_owner().ok_or(NativeCommandError::Conflict)?;
        let actor = control
            .original_administrative_actor()
            .ok_or(NativeCommandError::Conflict)?;
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(()),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        if !state.acquired {
            return Ok(());
        }
        let root = state.root as *const SourceRootSeal;
        let epoch = std::ptr::from_mut(state.epoch.as_mut()).cast::<c_void>();
        let Some(original) = state.command.as_mut() else {
            return Ok(());
        };
        if original.cut_handle == 0 {
            return Ok(());
        }
        if original.result.is_none() {
            let mut native = NativeResult::default();
            let status = (self.api.query_result)(
                root,
                epoch,
                original.cut_handle as *const SourceEffectCut,
                &mut native,
            );
            if status == -libc::EAGAIN {
                return Ok(());
            }
            if status != 0 {
                return Err(NativeCommandError::Conflict);
            }
            let result = native.portable()?;
            result.validate_against(&original.compute)?;
            if Some(result.cut_id.get()) != original.cut_id {
                return Err(NativeCommandError::Conflict);
            }
            // Cache the authentic immutable result before another fallible step.
            original.result = Some(result);
        }
        let result = original
            .result
            .as_ref()
            .ok_or(NativeCommandError::Conflict)?;
        if !original.replied {
            let credit = match original.credit.take() {
                Some(credit) => credit,
                None => match actor.reserve_construction_reply(original.cursor) {
                    Ok(credit) => credit,
                    Err(NativeAdministrativeInboxError::Busy) => return Ok(()),
                    Err(_) => return Err(NativeCommandError::Conflict),
                },
            };
            match actor.retain_reply(
                credit,
                &NativeFrame::EffectProgress(Box::new(result.clone())),
            ) {
                Ok(()) => original.replied = true,
                Err(NativeAdministrativeInboxError::Busy) => return Ok(()),
                Err(_) => return Err(NativeCommandError::Conflict),
            }
        }
        if original.published {
            return Ok(());
        }
        match actor.send_reply(original.cursor) {
            Ok(sent) => {
                original.published = sent;
                Ok(())
            }
            Err(NativeAdministrativeInboxError::Busy) => Ok(()),
            Err(_) => Err(NativeCommandError::Conflict),
        }
    }
}

fn position(native: NativeEffectPosition) -> Result<Position, NativeCommandError> {
    if native.reserved != 0 {
        return Err(NativeCommandError::Conflict);
    }
    let phase = match native.phase {
        0 => Phase::BoundaryControl,
        1 => Phase::Publication,
        2 => Phase::Delivery,
        3 => Phase::Reaction,
        _ => return Err(NativeCommandError::Conflict),
    };
    Ok(Position {
        time_ps: U64::new(native.time_ps),
        microstep: U64::new(native.microstep),
        phase,
    })
}

#[cfg(test)]
mod tests {
    //! Native-result ABI and refusal controls without issuing source authority.

    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn historical_native_result_matches_the_source_256_byte_contract() {
        assert_eq!(size_of::<NativeResult>(), 256);
        assert_eq!(offset_of!(NativeResult, scope), 8);
        assert_eq!(offset_of!(NativeResult, command), 104);
        assert_eq!(offset_of!(NativeResult, sequence), 136);
        assert_eq!(offset_of!(NativeResult, evaluated), 168);
        assert_eq!(offset_of!(NativeResult, evaluation_id), 192);
        assert_eq!(offset_of!(NativeResult, resulting), 208);
        assert_eq!(offset_of!(NativeResult, returned_service_count), 232);
        assert_eq!(offset_of!(NativeResult, status), 240);
        assert_eq!(offset_of!(NativeResult, end_result), 248);
    }

    #[test]
    fn native_result_conversion_refuses_unknown_or_reserved_shapes() {
        let malformed = [
            NativeResult {
                version: 2,
                ..original_shape()
            },
            NativeResult {
                size: 255,
                ..original_shape()
            },
            NativeResult {
                status: 4,
                ..original_shape()
            },
            NativeResult {
                flags: 1,
                ..original_shape()
            },
            NativeResult {
                reserved: 1,
                ..original_shape()
            },
            NativeResult {
                evaluated: NativeEffectPosition {
                    phase: 4,
                    ..Default::default()
                },
                ..original_shape()
            },
            NativeResult {
                resulting: NativeEffectPosition {
                    reserved: 1,
                    ..Default::default()
                },
                ..original_shape()
            },
        ];

        for original in malformed {
            assert!(matches!(
                original.portable(),
                Err(NativeCommandError::Conflict)
            ));
        }
    }

    #[test]
    fn effects_unknown_preserves_signed_failure_and_counter_regression() {
        // These copied scalars are an ABI conversion fixture, not a native
        // receipt or an epoch permit. Conversion must not repair uncertainty.
        let original = NativeResult {
            raw_before: 7,
            raw_after: 6,
            status: 3,
            end_result: -libc::EOWNERDEAD,
            ..original_shape()
        };

        let copied = original.portable();

        assert!(matches!(copied, Ok(ref result)
            if result.status == NativeEffectProgressStatus::EffectsUnknown
                && result.raw_before.get() == 7
                && result.raw_after.get() == 6
                && result.returned_service_count.get() == 0
                && result.end_result == -libc::EOWNERDEAD));
    }

    fn original_shape() -> NativeResult {
        NativeResult {
            version: 1,
            size: 256,
            status: 1,
            ..Default::default()
        }
    }
}

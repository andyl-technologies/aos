//! Transactional writeback for shared lexical environment cells.
//!
//! Captured lambda and thunk environments hold [`EvalFrame`] values behind
//! [`Arc`]. A moving collection therefore cannot repair one cloned closure
//! payload: it must rewrite the shared [`AtomicValueCell`](super::super::env::AtomicValueCell)
//! that every capture observes. This module validates those targets during
//! heap-field staging and defers the actual stores until the surrounding live
//! commit has completed every fallible operation.

use std::collections::TryReserveError;
use std::sync::Arc;

use super::{
    CapturedRootOwner, EvalEnv, EvalEnvError, EvalThunkKind, FlatClosurePayload, HeapEdgeSource,
    HeapObjectValue, Value,
};
use crate::eval::EvalFrame;

/// Shared frame-slot rewrites deferred until the live commit.
pub(super) struct EnvironmentWritebackStage {
    writebacks: Vec<StagedEnvironmentWriteback>,
}

struct StagedEnvironmentWriteback {
    frame: Arc<EvalFrame>,
    slot: u32,
    replacement: Value,
}

/// Returns whether `source` names a writable captured environment cell.
///
/// # Errors
///
/// Returns [`EvalEnvError`] if the source names a frame slot that cannot be
/// written under the frame's current publication/borrow state.
pub(super) fn validate_captured_environment_source(
    object: &HeapObjectValue,
    source: &HeapEdgeSource,
) -> Result<bool, EvalEnvError> {
    let Some((frame, slot)) = captured_environment_target(object, source) else {
        return Ok(false);
    };
    let Ok(slot) = u32::try_from(slot) else {
        return Ok(false);
    };
    frame.validate_set(slot)?;
    Ok(true)
}

/// Returns whether `source` names a writable frame captured by a flat closure.
///
/// # Errors
///
/// Returns [`EvalEnvError`] if the named frame slot cannot be written under its
/// current publication or borrow state.
pub(super) fn validate_flat_closure_captured_environment_source(
    payload: &FlatClosurePayload,
    source: &HeapEdgeSource,
) -> Result<bool, EvalEnvError> {
    let (env, owner) = match payload {
        FlatClosurePayload::Lambda(lambda) => (lambda.env(), CapturedRootOwner::Lambda),
        FlatClosurePayload::Thunk(thunk) => match thunk.kind() {
            EvalThunkKind::Node { env, .. } => (env, CapturedRootOwner::Thunk),
            _ => return Ok(false),
        },
        FlatClosurePayload::SharedThunk(thunk) => match thunk.kind() {
            EvalThunkKind::Node { env, .. } => (env, CapturedRootOwner::Thunk),
            _ => return Ok(false),
        },
        FlatClosurePayload::Primop(_) | FlatClosurePayload::Retired(_) => return Ok(false),
    };
    validate_captured_environment_source_for_env(env, owner, source)
}

impl EnvironmentWritebackStage {
    /// Creates storage for at most `entries` shared-cell rewrites.
    ///
    /// # Errors
    ///
    /// Returns [`TryReserveError`] if the stage cannot reserve its backing
    /// storage.
    pub(super) fn try_new(entries: usize) -> Result<Self, TryReserveError> {
        let mut writebacks = Vec::new();
        writebacks.try_reserve_exact(entries)?;
        Ok(Self { writebacks })
    }

    /// Stages one captured environment rewrite when `source` names such a cell.
    ///
    /// Duplicate entries are safe: shared frames can appear through several
    /// closure owners and every forwarding rewrite stores the same replacement.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError`] if the source names a frame slot that cannot be
    /// written under the frame's current publication/borrow state.
    pub(super) fn stage(
        &mut self,
        object: &HeapObjectValue,
        source: &HeapEdgeSource,
        replacement: Value,
    ) -> Result<bool, EvalEnvError> {
        let Some((frame, slot)) = captured_environment_target(object, source) else {
            return Ok(false);
        };
        let Ok(slot) = u32::try_from(slot) else {
            return Ok(false);
        };
        frame.validate_set(slot)?;
        self.writebacks.push(StagedEnvironmentWriteback {
            frame: Arc::clone(frame),
            slot,
            replacement,
        });
        Ok(true)
    }

    /// Stages one shared frame rewrite owned by a flat closure.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError`] if the source names a frame slot that cannot be
    /// written under the frame's current publication or borrow state.
    pub(super) fn stage_flat_closure(
        &mut self,
        payload: &FlatClosurePayload,
        source: &HeapEdgeSource,
        replacement: Value,
    ) -> Result<bool, EvalEnvError> {
        let (env, owner) = match payload {
            FlatClosurePayload::Lambda(lambda) => (lambda.env(), CapturedRootOwner::Lambda),
            FlatClosurePayload::Thunk(thunk) => match thunk.kind() {
                EvalThunkKind::Node { env, .. } => (env, CapturedRootOwner::Thunk),
                _ => return Ok(false),
            },
            FlatClosurePayload::SharedThunk(thunk) => match thunk.kind() {
                EvalThunkKind::Node { env, .. } => (env, CapturedRootOwner::Thunk),
                _ => return Ok(false),
            },
            FlatClosurePayload::Primop(_) | FlatClosurePayload::Retired(_) => return Ok(false),
        };
        let Some((frame, slot)) = captured_environment_target_for_env(env, owner, source) else {
            return Ok(false);
        };
        let Ok(slot) = u32::try_from(slot) else {
            return Ok(false);
        };
        frame.validate_set(slot)?;
        self.writebacks.push(StagedEnvironmentWriteback {
            frame: Arc::clone(frame),
            slot,
            replacement,
        });
        Ok(true)
    }

    /// Commits prevalidated shared frame-slot rewrites without allocation.
    pub(super) fn commit(self) {
        for writeback in self.writebacks {
            if let Err(error) = writeback.frame.set(writeback.slot, writeback.replacement) {
                unreachable!("staged environment writeback failed to commit: {error}");
            }
        }
    }
}

fn captured_environment_target<'a>(
    object: &'a HeapObjectValue,
    source: &HeapEdgeSource,
) -> Option<(&'a Arc<EvalFrame>, usize)> {
    let HeapEdgeSource::CapturedEnv { owner, frame, slot } = source else {
        return None;
    };
    let env = match (object, owner) {
        (HeapObjectValue::Lambda(lambda), CapturedRootOwner::Lambda) => lambda.env(),
        (HeapObjectValue::Thunk(thunk), CapturedRootOwner::Thunk) => match thunk.kind() {
            EvalThunkKind::Node { env, .. } => env,
            _ => return None,
        },
        _ => return None,
    };
    captured_frame(env, *frame).map(|frame| (frame, *slot))
}

fn validate_captured_environment_source_for_env(
    env: &EvalEnv,
    owner: CapturedRootOwner,
    source: &HeapEdgeSource,
) -> Result<bool, EvalEnvError> {
    let Some((frame, slot)) = captured_environment_target_for_env(env, owner, source) else {
        return Ok(false);
    };
    let Ok(slot) = u32::try_from(slot) else {
        return Ok(false);
    };
    frame.validate_set(slot)?;
    Ok(true)
}

fn captured_environment_target_for_env<'a>(
    env: &'a EvalEnv,
    expected_owner: CapturedRootOwner,
    source: &HeapEdgeSource,
) -> Option<(&'a Arc<EvalFrame>, usize)> {
    let HeapEdgeSource::CapturedEnv { owner, frame, slot } = source else {
        return None;
    };
    if *owner != expected_owner {
        return None;
    }
    captured_frame(env, *frame).map(|frame| (frame, *slot))
}

fn captured_frame(env: &EvalEnv, index: usize) -> Option<&Arc<EvalFrame>> {
    env.frames().get(index)
}

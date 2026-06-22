//! Lexical and dynamic environment captures for the tree-walk evaluator.
//!
//! The tree-walk oracle stores active lexical frames as shared slot arrays so
//! thunks can capture the frame graph at allocation time. Slots are filled after
//! the frame is pushed, which supports Nix's self-visible `let` bindings and
//! lets recursive thunks blackhole through the ordinary thunk state machine.
//! Dynamic `with` scopes and scoped-import globals are captured alongside
//! lexical frames so escaping thunks and closures preserve the same runtime
//! lookup chain.

use std::cell::RefCell;
use std::rc::Rc;

use thiserror::Error;

use super::module::{EvalModuleId, EvalNodeRef};
use crate::compile::IrId;
use crate::value::Value;

/// A captured lexical environment snapshot.
#[derive(Clone, Debug, Default)]
pub struct EvalEnv {
    frames: Box<[Rc<EvalFrame>]>,
}

impl EvalEnv {
    /// Captures the active frame stack.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::CaptureAllocationFailed`] if the snapshot frame
    /// list cannot be reserved.
    pub fn capture(frames: &[Rc<EvalFrame>]) -> Result<Self, EvalEnvError> {
        let mut captured = Vec::new();
        captured.try_reserve_exact(frames.len()).map_err(|_| {
            EvalEnvError::CaptureAllocationFailed {
                frames: frames.len(),
            }
        })?;
        captured.extend_from_slice(frames);
        Ok(Self {
            frames: captured.into_boxed_slice(),
        })
    }

    /// Returns the captured frame stack, ordered outermost to innermost.
    pub fn frames(&self) -> &[Rc<EvalFrame>] {
        &self.frames
    }
}

/// A captured dynamic `with` scope stack.
#[derive(Clone, Debug, Default)]
pub struct EvalWithEnv {
    scopes: Box<[EvalWithScope]>,
}

impl EvalWithEnv {
    /// Captures the active `with` scope stack.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::WithCaptureAllocationFailed`] if the snapshot
    /// scope list cannot be reserved.
    pub fn capture(scopes: &[EvalWithScope]) -> Result<Self, EvalEnvError> {
        let mut captured = Vec::new();
        captured.try_reserve_exact(scopes.len()).map_err(|_| {
            EvalEnvError::WithCaptureAllocationFailed {
                scopes: scopes.len(),
            }
        })?;
        captured.extend_from_slice(scopes);
        Ok(Self {
            scopes: captured.into_boxed_slice(),
        })
    }

    /// Returns the captured `with` scopes, ordered outermost to innermost.
    pub fn scopes(&self) -> &[EvalWithScope] {
        &self.scopes
    }
}

/// A captured scoped-import global scope stack.
#[derive(Clone, Debug, Default)]
pub struct EvalScopedGlobalEnv {
    scopes: Box<[Value]>,
}

impl EvalScopedGlobalEnv {
    /// Captures the active scoped-import global scope stack.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::ScopedGlobalCaptureAllocationFailed`] if the
    /// snapshot scope list cannot be reserved.
    pub fn capture(scopes: &[Value]) -> Result<Self, EvalEnvError> {
        let mut captured = Vec::new();
        captured.try_reserve_exact(scopes.len()).map_err(|_| {
            EvalEnvError::ScopedGlobalCaptureAllocationFailed {
                scopes: scopes.len(),
            }
        })?;
        captured.extend_from_slice(scopes);
        Ok(Self {
            scopes: captured.into_boxed_slice(),
        })
    }

    /// Returns the captured scoped-import globals, ordered outermost to innermost.
    pub fn scopes(&self) -> &[Value] {
        &self.scopes
    }
}

/// One active dynamic `with` scope.
#[derive(Clone, Copy, Debug)]
pub struct EvalWithScope {
    scope: EvalNodeRef,
    value: Value,
}

impl EvalWithScope {
    /// Creates an active `with` scope entry.
    pub const fn new(module: EvalModuleId, scope: IrId, value: Value) -> Self {
        Self {
            scope: EvalNodeRef::new(module, scope),
            value,
        }
    }

    /// Returns the module-qualified lowered scrutinee node for this scope.
    pub const fn scope_ref(&self) -> EvalNodeRef {
        self.scope
    }

    /// Returns the module that owns this scope's lowered scrutinee node.
    pub const fn module(&self) -> EvalModuleId {
        self.scope.module()
    }

    /// Returns the lowered scrutinee node for this scope.
    pub const fn scope(&self) -> IrId {
        self.scope.id()
    }

    /// Returns the lazy attrset value for this scope.
    pub const fn value(&self) -> Value {
        self.value
    }
}

/// One lexical frame's runtime slots.
#[derive(Debug)]
pub struct EvalFrame {
    slots: RefCell<Vec<Value>>,
}

impl EvalFrame {
    /// Creates a frame with `slot_count` unfilled slots.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::FrameAllocationFailed`] if the slot vector
    /// cannot be reserved.
    pub fn new(slot_count: usize) -> Result<Rc<Self>, EvalEnvError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(slot_count)
            .map_err(|_| EvalEnvError::FrameAllocationFailed { slots: slot_count })?;
        slots.resize(slot_count, Value::null());
        Ok(Rc::new(Self {
            slots: RefCell::new(slots),
        }))
    }

    /// Reads a slot value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::BorrowConflict`] if the frame is already mutably
    /// borrowed. Returns [`EvalEnvError::SlotOutOfBounds`] if `slot` is outside
    /// this frame.
    pub fn get(&self, slot: u32) -> Result<Value, EvalEnvError> {
        let slots = self
            .slots
            .try_borrow()
            .map_err(|_| EvalEnvError::BorrowConflict)?;
        slots
            .get(slot as usize)
            .copied()
            .ok_or(EvalEnvError::SlotOutOfBounds {
                slot,
                slots: slots.len(),
            })
    }

    /// Writes a slot value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalEnvError::BorrowConflict`] if the frame is already
    /// borrowed. Returns [`EvalEnvError::SlotOutOfBounds`] if `slot` is outside
    /// this frame.
    pub fn set(&self, slot: u32, value: Value) -> Result<(), EvalEnvError> {
        let mut slots = self
            .slots
            .try_borrow_mut()
            .map_err(|_| EvalEnvError::BorrowConflict)?;
        let len = slots.len();
        let Some(target) = slots.get_mut(slot as usize) else {
            return Err(EvalEnvError::SlotOutOfBounds { slot, slots: len });
        };
        *target = value;
        Ok(())
    }
}

/// A lexical environment operation failed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EvalEnvError {
    /// A frame's slot vector could not be allocated.
    #[error("failed to reserve {slots} environment slots")]
    FrameAllocationFailed {
        /// The requested number of frame slots.
        slots: usize,
    },
    /// A captured frame list could not be allocated.
    #[error("failed to reserve {frames} captured environment frames")]
    CaptureAllocationFailed {
        /// The requested number of captured frames.
        frames: usize,
    },
    /// A captured `with` scope list could not be allocated.
    #[error("failed to reserve {scopes} captured with scopes")]
    WithCaptureAllocationFailed {
        /// The requested number of captured `with` scopes.
        scopes: usize,
    },
    /// A captured scoped-import global scope list could not be allocated.
    #[error("failed to reserve {scopes} captured scoped-import globals")]
    ScopedGlobalCaptureAllocationFailed {
        /// The requested number of captured scoped-import global scopes.
        scopes: usize,
    },
    /// A frame was already borrowed in an incompatible mode.
    #[error("environment frame borrow conflict")]
    BorrowConflict,
    /// A slot index was outside the frame.
    #[error("environment slot {slot} out of bounds for {slots} slots")]
    SlotOutOfBounds {
        /// The requested slot.
        slot: u32,
        /// The number of slots available in the frame.
        slots: usize,
    },
}

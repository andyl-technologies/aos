//! Module identifiers for multi-file tree-walk evaluation.
//!
//! Imported Nix files keep their lowered IR as separate modules. Runtime
//! closures and thunks carry module-qualified node references so deferred work
//! can be forced after the evaluator has returned to another file.

use crate::compile::IrId;

/// Identifies one lowered IR module loaded into a tree-walk evaluator.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvalModuleId(u32);

impl EvalModuleId {
    /// The module id assigned to the evaluator's root IR.
    pub const ROOT: Self = Self(0);

    /// Creates a module id from a raw module-table index.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw `u32` module id.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the module id as a `usize` index.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A module-qualified lowered IR node reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EvalNodeRef {
    module: EvalModuleId,
    id: IrId,
}

impl EvalNodeRef {
    /// Creates a module-qualified IR node reference.
    pub const fn new(module: EvalModuleId, id: IrId) -> Self {
        Self { module, id }
    }

    /// Returns the module that owns this node.
    pub const fn module(self) -> EvalModuleId {
        self.module
    }

    /// Returns the node id inside its module.
    pub const fn id(self) -> IrId {
        self.id
    }
}

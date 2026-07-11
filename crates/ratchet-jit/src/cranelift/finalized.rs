//! Finalized executable-function metadata and reachable stack-map tables.

use std::ptr::NonNull;

use crate::tier::JitCompiledCodePointer;

use super::{JitCraneliftDefinedFunction, JitCraneliftUserStackMap};

/// A verified CLIF artifact finalized into executable memory.
///
/// The code pointer stored here is metadata tied to the lifetime of the owning
/// Cranelift module. It is not a standalone ownership handle. The runtime map
/// table may additionally include maps from a module-local tier-2 body reached
/// through the exported entry adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitCraneliftFinalizedFunction {
    defined_function: JitCraneliftDefinedFunction,
    runtime_user_stack_maps: Vec<JitCraneliftUserStackMap>,
    code_ptr: NonNull<u8>,
}

impl JitCraneliftFinalizedFunction {
    pub(super) fn new(
        defined_function: JitCraneliftDefinedFunction,
        code_ptr: NonNull<u8>,
    ) -> Self {
        let runtime_user_stack_maps = defined_function.user_stack_maps().to_vec();
        Self {
            defined_function,
            runtime_user_stack_maps,
            code_ptr,
        }
    }

    pub(super) fn new_with_runtime_user_stack_maps(
        defined_function: JitCraneliftDefinedFunction,
        code_ptr: NonNull<u8>,
        runtime_user_stack_maps: Vec<JitCraneliftUserStackMap>,
    ) -> Self {
        Self {
            defined_function,
            runtime_user_stack_maps,
            code_ptr,
        }
    }

    /// Returns the artifact body that was finalized.
    pub const fn defined_function(&self) -> &JitCraneliftDefinedFunction {
        &self.defined_function
    }

    /// Returns every stack map reachable from this finalized entrypoint.
    pub fn runtime_user_stack_maps(&self) -> &[JitCraneliftUserStackMap] {
        &self.runtime_user_stack_maps
    }

    /// Returns the stable module symbol name for the finalized artifact body.
    pub fn symbol_name(&self) -> &str {
        self.defined_function.symbol_name()
    }

    /// Returns the opaque finalized code pointer.
    ///
    /// Callers must not cast or invoke this pointer outside the reviewed native
    /// call boundaries. Its validity is tied to the owning Cranelift module.
    pub const fn code_ptr(&self) -> NonNull<u8> {
        self.code_ptr
    }

    /// Returns the finalized code pointer as tier-slot metadata.
    pub const fn compiled_code_ptr(&self) -> JitCompiledCodePointer {
        JitCompiledCodePointer::from_non_null(self.code_ptr)
    }
}

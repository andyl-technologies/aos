//! Rust-callable / ABI-signature / native-export allocation descriptor types,
//! split from [`super`].

use super::*;

/// The Rust function shape behind a callable allocation storage wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationRustCallableShape {
    /// `fn(&mut RuntimeAllocator) -> Result<ArenaAllocation, ArenaError>`.
    AllocatorOnly,
    /// `fn(&mut RuntimeAllocator, u32, u32) -> Result<ArenaAllocation, ArenaError>`.
    AllocatorU32U32,
    /// `fn(&mut RuntimeAllocator, usize) -> Result<ArenaAllocation, ArenaError>`.
    AllocatorUsize,
    /// `fn(&mut RuntimeAllocator, usize, usize, u32) -> Result<ArenaAllocation, ArenaError>`.
    AllocatorUsizeUsizeU32,
}

/// A process-local callable Rust storage-wrapper address.
///
/// This pointer identifies a Rust function in the current process. It is used as
/// registration metadata for later native startup binding and is intentionally
/// not serialized or treated as stable ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationRustCallableAddress {
    ptr: *const (),
}

impl RuntimeAllocationRustCallableAddress {
    pub(in crate::runtime::alloc) const fn new(ptr: *const ()) -> Self {
        Self { ptr }
    }

    /// Returns the process-local function pointer.
    pub const fn as_ptr(self) -> *const () {
        self.ptr
    }

    /// Returns true when the address pointer is non-null.
    pub const fn is_non_null(self) -> bool {
        !self.ptr.is_null()
    }
}

/// A callable Rust storage-wrapper binding for one allocation helper entry point.
///
/// This is not a native ABI binding. It deliberately omits
/// [`RuntimeAllocationAbiSignature`] because these Rust callables return
/// [`ArenaAllocation`] through [`Result`] and some shapes omit semantic native
/// payloads that the frozen ABI will eventually initialize.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationRustCallableBinding {
    entrypoint: RuntimeAllocationEntryPoint,
    shape: RuntimeAllocationRustCallableShape,
    address: RuntimeAllocationRustCallableAddress,
}

impl RuntimeAllocationRustCallableBinding {
    pub(in crate::runtime::alloc) const fn new(
        entrypoint: RuntimeAllocationEntryPoint,
        shape: RuntimeAllocationRustCallableShape,
        address: RuntimeAllocationRustCallableAddress,
    ) -> Self {
        Self {
            entrypoint,
            shape,
            address,
        }
    }

    /// Returns the allocation entry point served by this binding.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.entrypoint
    }

    /// Returns the Rust function shape behind this binding.
    pub const fn shape(self) -> RuntimeAllocationRustCallableShape {
        self.shape
    }

    /// Returns the stable runtime symbol name served by this binding.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the process-local callable Rust address for this binding.
    pub const fn address(self) -> RuntimeAllocationRustCallableAddress {
        self.address
    }
}

/// A missing piece before a storage-only allocation helper can become a native ABI export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationNativeExportBlocker {
    /// No final exported C ABI wrapper is admitted for the frozen helper name.
    MissingFinalExportedWrapper,
    /// Native wrappers cannot yet decode the runtime context pointer.
    RuntimeContextAbiUnimplemented,
    /// Helper failures cannot yet transfer into evaluator trap/error machinery.
    TrapTransferUnimplemented,
    /// Pointer-shaped ABI returns are not yet materialized as typed heap objects.
    TypedPointerReturnUnmaterialized,
    /// The frozen ABI's semantic payloads are not initialized by the storage wrapper.
    SemanticPayloadInitializationUnimplemented,
}

pub(in crate::runtime::alloc) const ALLOCATION_STORAGE_NATIVE_EXPORT_BLOCKERS:
    &[RuntimeAllocationNativeExportBlocker] = &[
    RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
    RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
    RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
];

pub(in crate::runtime::alloc) const ALLOCATION_SEMANTIC_NATIVE_EXPORT_BLOCKERS:
    &[RuntimeAllocationNativeExportBlocker] = &[
    RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
    RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
    RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
    RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
    RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented,
];

/// Native-export readiness for one frozen allocation helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationNativeExportReadiness {
    entrypoint: RuntimeAllocationEntryPoint,
    abi_signature: RuntimeAllocationAbiSignature,
    rust_callable_binding: RuntimeAllocationRustCallableBinding,
    blockers: &'static [RuntimeAllocationNativeExportBlocker],
}

impl RuntimeAllocationNativeExportReadiness {
    pub(in crate::runtime::alloc) fn for_entrypoint(
        entrypoint: RuntimeAllocationEntryPoint,
    ) -> Self {
        Self {
            entrypoint,
            abi_signature: entrypoint.abi_signature(),
            rust_callable_binding: entrypoint.rust_callable_binding(),
            blockers: entrypoint.native_export_blockers(),
        }
    }

    /// Returns the allocation entry point served by this readiness record.
    pub const fn entrypoint(&self) -> RuntimeAllocationEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this readiness record.
    pub const fn symbol_name(&self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the frozen native ABI signature for this allocation helper.
    pub const fn abi_signature(&self) -> RuntimeAllocationAbiSignature {
        self.abi_signature
    }

    /// Returns the current storage-only Rust callable binding.
    pub const fn rust_callable_binding(&self) -> RuntimeAllocationRustCallableBinding {
        self.rust_callable_binding
    }

    /// Returns the current blockers before this helper can be a native ABI export.
    pub const fn blockers(&self) -> &'static [RuntimeAllocationNativeExportBlocker] {
        self.blockers
    }

    /// Returns true when this helper has exported native ABI metadata.
    pub const fn is_export_ready(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// Native-export readiness report for frozen allocation helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationNativeExportPreflight {
    readiness: Vec<RuntimeAllocationNativeExportReadiness>,
}

impl RuntimeAllocationNativeExportPreflight {
    pub(in crate::runtime::alloc) fn new(
        readiness: Vec<RuntimeAllocationNativeExportReadiness>,
    ) -> Self {
        Self { readiness }
    }

    /// Returns allocation native-export readiness in runtime entry-point order.
    pub fn readiness(&self) -> &[RuntimeAllocationNativeExportReadiness] {
        &self.readiness
    }

    /// Returns true when every allocation helper has native ABI export metadata.
    pub fn is_complete(&self) -> bool {
        self.readiness.iter().all(|record| record.is_export_ready())
    }

    /// Returns the readiness record for `symbol_name`, when present.
    pub fn readiness_for_symbol(
        &self,
        symbol_name: &str,
    ) -> Option<&RuntimeAllocationNativeExportReadiness> {
        self.readiness
            .iter()
            .find(|record| record.symbol_name() == symbol_name)
    }
}

/// A frozen allocation-helper ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationAbiSignature {
    entrypoint: RuntimeAllocationEntryPoint,
    parameters: &'static [RuntimeAllocationAbiParameter],
    return_kind: RuntimeAllocationAbiReturnKind,
}

impl RuntimeAllocationAbiSignature {
    pub(in crate::runtime::alloc) const fn new(
        entrypoint: RuntimeAllocationEntryPoint,
        parameters: &'static [RuntimeAllocationAbiParameter],
        return_kind: RuntimeAllocationAbiReturnKind,
    ) -> Self {
        Self {
            entrypoint,
            parameters,
            return_kind,
        }
    }

    /// Returns the allocation ABI signature for a frozen runtime symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        RuntimeAllocationEntryPoint::from_symbol_name(symbol_name)
            .map(RuntimeAllocationEntryPoint::abi_signature)
    }

    /// Returns the allocation entry point served by this signature.
    pub const fn entrypoint(self) -> RuntimeAllocationEntryPoint {
        self.entrypoint
    }

    /// Returns the stable runtime symbol name for this signature.
    pub const fn symbol_name(self) -> &'static str {
        self.entrypoint.symbol_name()
    }

    /// Returns the ordered ABI parameters for this signature.
    pub const fn parameters(self) -> &'static [RuntimeAllocationAbiParameter] {
        self.parameters
    }

    /// Returns the ABI result kind produced by this signature.
    pub const fn return_kind(self) -> RuntimeAllocationAbiReturnKind {
        self.return_kind
    }
}

/// A parameter accepted by a frozen allocation-helper ABI signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAllocationAbiParameter {
    name: &'static str,
    kind: RuntimeAllocationAbiParameterKind,
}

impl RuntimeAllocationAbiParameter {
    pub(in crate::runtime::alloc) const fn new(
        name: &'static str,
        kind: RuntimeAllocationAbiParameterKind,
    ) -> Self {
        Self { name, kind }
    }

    /// Returns the stable ABI parameter name.
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the machine-level kind carried by this parameter.
    pub const fn kind(self) -> RuntimeAllocationAbiParameterKind {
        self.kind
    }
}

/// A machine-level parameter kind accepted by allocation-helper symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationAbiParameterKind {
    /// The evaluator runtime context that owns the installed allocator strategy.
    RuntimeContext,
    /// A pointer to native code for a thunk or lambda body.
    CodePointer,
    /// A pointer to a captured environment frame.
    EnvPointer,
    /// A by-value runtime value word pair.
    Value,
    /// A pointer to a runtime list object.
    ListPointer,
    /// A hidden-class shape identifier.
    ShapeId,
    /// A target-pointer-sized unsigned integer.
    Usize,
    /// A runtime-specific raw allocation type tag.
    TypeTag,
    /// A 32-bit unsigned integer.
    U32,
}

/// The success-path machine-level result kind returned by allocation-helper symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeAllocationAbiReturnKind {
    /// A pointer to a thunk object.
    ThunkPointer,
    /// A pointer to a lambda closure object.
    LambdaPointer,
    /// A pointer to an attrset object.
    AttrsPointer,
    /// A pointer to a list object.
    ListPointer,
    /// A pointer to a string header object.
    StringHeaderPointer,
    /// A pointer to raw heap storage.
    RawPointer,
}

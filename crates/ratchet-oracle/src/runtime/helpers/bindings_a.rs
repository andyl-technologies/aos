//! Rust-callable, ABI-signature, and native-target-candidate binding families,
//! split from [`super`] (RFC-0007 §2 file-size cap).

use super::*;

/// A callable Rust storage-wrapper binding for one runtime helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeHelperRustCallableBinding {
    /// An allocation helper backed by `runtime::alloc` storage-wrapper dispatch.
    Allocation(RuntimeAllocationRustCallableBinding),
    /// A call-control helper backed by `runtime::apply` evaluator-wrapper dispatch.
    CallControl(RuntimeApplyRustCallableBinding),
    /// An attrset-access helper backed by `runtime::attr` evaluator-wrapper dispatch.
    AttrsetAccess(RuntimeAttrAccessRustCallableBinding),
    /// An environment-access helper backed by `runtime::env` storage-wrapper dispatch.
    EnvironmentAccess(RuntimeEnvAccessRustCallableBinding),
    /// A forcing helper backed by `runtime::forcing` evaluator-wrapper dispatch.
    Forcing(RuntimeForcingRustCallableBinding),
    /// A write-barrier helper backed by `runtime::barrier` storage-wrapper dispatch.
    WriteBarrier(RuntimeWriteBarrierRustCallableBinding),
}

impl RuntimeHelperRustCallableBinding {
    /// Returns the stable helper symbol name served by this callable binding.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::Allocation(binding) => binding.symbol_name(),
            Self::CallControl(binding) => binding.symbol_name(),
            Self::AttrsetAccess(binding) => binding.symbol_name(),
            Self::EnvironmentAccess(binding) => binding.symbol_name(),
            Self::Forcing(binding) => binding.symbol_name(),
            Self::WriteBarrier(binding) => binding.symbol_name(),
        }
    }

    /// Returns the core helper role served by this callable binding.
    pub const fn role(self) -> RuntimeHelperRole {
        match self {
            Self::Allocation(_) => RuntimeHelperRole::Allocation,
            Self::CallControl(_) => RuntimeHelperRole::CallControl,
            Self::AttrsetAccess(_) => RuntimeHelperRole::AttrsetAccess,
            Self::EnvironmentAccess(_) => RuntimeHelperRole::EnvironmentAccess,
            Self::Forcing(_) => RuntimeHelperRole::ForcingControl,
            Self::WriteBarrier(_) => RuntimeHelperRole::WriteBarrier,
        }
    }

    /// Returns the safe helper binding metadata associated with this callable.
    pub const fn helper_binding(self) -> RuntimeHelperBinding {
        match self {
            Self::Allocation(binding) => {
                RuntimeHelperBinding::Allocation(binding.entrypoint().abi_signature())
            }
            Self::CallControl(binding) => {
                RuntimeHelperBinding::CallControl(binding.entrypoint().abi_signature())
            }
            Self::AttrsetAccess(binding) => {
                RuntimeHelperBinding::AttrsetAccess(binding.entrypoint().abi_signature())
            }
            Self::EnvironmentAccess(binding) => {
                RuntimeHelperBinding::EnvironmentAccess(binding.entrypoint().abi_signature())
            }
            Self::Forcing(binding) => {
                RuntimeHelperBinding::Forcing(binding.entrypoint().abi_signature())
            }
            Self::WriteBarrier(binding) => {
                RuntimeHelperBinding::WriteBarrier(binding.entrypoint().abi_signature())
            }
        }
    }

    /// Returns the allocation callable when this binding serves allocation.
    pub const fn allocation_callable(self) -> Option<RuntimeAllocationRustCallableBinding> {
        match self {
            Self::Allocation(binding) => Some(binding),
            Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns the call-control callable when this binding serves apply/call control.
    pub const fn call_control_callable(self) -> Option<RuntimeApplyRustCallableBinding> {
        match self {
            Self::CallControl(binding) => Some(binding),
            Self::Allocation(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns the attrset-access callable when this binding serves attrset access.
    pub const fn attrset_access_callable(self) -> Option<RuntimeAttrAccessRustCallableBinding> {
        match self {
            Self::AttrsetAccess(binding) => Some(binding),
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns the environment-access callable when this binding serves environment access.
    pub const fn env_access_callable(self) -> Option<RuntimeEnvAccessRustCallableBinding> {
        match self {
            Self::EnvironmentAccess(binding) => Some(binding),
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns the forcing callable when this binding serves forcing control.
    pub const fn forcing_callable(self) -> Option<RuntimeForcingRustCallableBinding> {
        match self {
            Self::Forcing(binding) => Some(binding),
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns the write-barrier callable when this binding serves a barrier.
    pub const fn write_barrier_callable(self) -> Option<RuntimeWriteBarrierRustCallableBinding> {
        match self {
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_) => None,
            Self::WriteBarrier(binding) => Some(binding),
        }
    }
}

/// A deterministic helper-family report for callable Rust storage wrappers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeHelperRustCallablePreflight {
    callable_bindings: Vec<RuntimeHelperRustCallableBinding>,
    missing_bindings: Vec<RuntimeHelperBinding>,
}

impl RuntimeHelperRustCallablePreflight {
    pub(in crate::runtime::helpers) fn new(
        callable_bindings: Vec<RuntimeHelperRustCallableBinding>,
        missing_bindings: Vec<RuntimeHelperBinding>,
    ) -> Self {
        Self {
            callable_bindings,
            missing_bindings,
        }
    }

    /// Returns helper bindings that have callable Rust storage wrappers.
    pub fn callable_bindings(&self) -> &[RuntimeHelperRustCallableBinding] {
        &self.callable_bindings
    }

    /// Returns bound helper metadata that still lacks a callable Rust wrapper.
    pub fn missing_bindings(&self) -> &[RuntimeHelperBinding] {
        &self.missing_bindings
    }

    /// Returns true when every currently bound helper has a callable Rust wrapper.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }
}

/// ABI-signature metadata for one runtime symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolAbiSignatureBinding {
    /// A helper symbol backed by safe helper metadata and a core call signature.
    Helper(RuntimeHelperBinding),
    /// A builtin symbol backed by frozen primop call-signature metadata.
    Builtin(RuntimeBuiltinCallBinding),
}

impl RuntimeSymbolAbiSignatureBinding {
    /// Returns the stable runtime symbol name served by this binding.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::Helper(binding) => binding.symbol_name(),
            Self::Builtin(binding) => binding.symbol_name(),
        }
    }

    /// Returns helper metadata when this binding serves a helper symbol.
    pub const fn helper_binding(&self) -> Option<RuntimeHelperBinding> {
        match self {
            Self::Helper(binding) => Some(*binding),
            Self::Builtin(_) => None,
        }
    }

    /// Returns builtin call metadata when this binding serves a builtin symbol.
    pub const fn builtin_call_binding(&self) -> Option<&RuntimeBuiltinCallBinding> {
        match self {
            Self::Helper(_) => None,
            Self::Builtin(binding) => Some(binding),
        }
    }

    /// Returns the core runtime-call signature represented by this binding.
    pub fn core_call_signature(&self) -> Option<RuntimeCallSignature> {
        match self {
            Self::Helper(binding) => binding.core_call_signature(),
            Self::Builtin(binding) => Some(binding.signature()),
        }
    }
}

/// One runtime symbol that still lacks ABI-signature registration metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolAbiMissingBinding {
    /// A helper symbol has no complete ABI-signature metadata yet.
    Helper {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The helper role reserved by the core runtime ABI.
        role: RuntimeHelperRole,
    },
    /// A builtin symbol is not currently a callable runtime wrapper.
    Builtin(RuntimeBuiltinCallMissingBinding),
    /// A builtin symbol was not classified by the builtin call manifest.
    UnclassifiedBuiltin {
        /// The stable runtime symbol name.
        symbol_name: String,
    },
}

impl RuntimeSymbolAbiMissingBinding {
    pub(in crate::runtime::helpers) fn helper(
        symbol_name: String,
        role: RuntimeHelperRole,
    ) -> Self {
        Self::Helper { symbol_name, role }
    }

    pub(in crate::runtime::helpers) fn builtin_unclassified(symbol_name: String) -> Self {
        Self::UnclassifiedBuiltin { symbol_name }
    }

    pub(in crate::runtime::helpers) fn from_binding_manifest_entry(
        entry: &RuntimeSymbolBindingManifestEntry,
    ) -> Self {
        match entry.status() {
            RuntimeSymbolBindingStatus::BoundHelper(binding) => {
                Self::helper(entry.symbol_name().to_owned(), binding.role())
            }
            RuntimeSymbolBindingStatus::UnboundHelper(role) => {
                Self::helper(entry.symbol_name().to_owned(), role)
            }
            RuntimeSymbolBindingStatus::Builtin => {
                Self::builtin_unclassified(entry.symbol_name().to_owned())
            }
        }
    }

    /// Returns the stable runtime symbol name that is not yet bindable.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::Helper { symbol_name, .. } | Self::UnclassifiedBuiltin { symbol_name } => {
                symbol_name
            }
            Self::Builtin(binding) => binding.symbol_name(),
        }
    }

    /// Returns the helper role when the missing binding is a helper symbol.
    pub const fn helper_role(&self) -> Option<RuntimeHelperRole> {
        match self {
            Self::Helper { role, .. } => Some(*role),
            Self::Builtin(_) | Self::UnclassifiedBuiltin { .. } => None,
        }
    }

    /// Returns builtin missing-binding metadata when this gap is a builtin.
    pub const fn builtin_missing_binding(&self) -> Option<&RuntimeBuiltinCallMissingBinding> {
        match self {
            Self::Builtin(binding) => Some(binding),
            Self::Helper { .. } | Self::UnclassifiedBuiltin { .. } => None,
        }
    }
}

/// The complete set of runtime-symbol ABI signatures required before native binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolAbiSignaturePlan {
    signature_bindings: Vec<RuntimeSymbolAbiSignatureBinding>,
}

impl RuntimeSymbolAbiSignaturePlan {
    pub(in crate::runtime::helpers) fn new(
        signature_bindings: Vec<RuntimeSymbolAbiSignatureBinding>,
    ) -> Self {
        Self { signature_bindings }
    }

    /// Returns ABI-signature metadata in runtime symbol-manifest projection order.
    pub fn signature_bindings(&self) -> &[RuntimeSymbolAbiSignatureBinding] {
        &self.signature_bindings
    }
}

/// A deterministic runtime-symbol report for ABI-signature metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolAbiSignaturePreflight {
    signature_bindings: Vec<RuntimeSymbolAbiSignatureBinding>,
    missing_bindings: Vec<RuntimeSymbolAbiMissingBinding>,
}

impl RuntimeSymbolAbiSignaturePreflight {
    pub(in crate::runtime::helpers) fn new(
        signature_bindings: Vec<RuntimeSymbolAbiSignatureBinding>,
        missing_bindings: Vec<RuntimeSymbolAbiMissingBinding>,
    ) -> Self {
        Self {
            signature_bindings,
            missing_bindings,
        }
    }

    /// Returns ABI-signature metadata in runtime symbol-manifest projection order.
    pub fn signature_bindings(&self) -> &[RuntimeSymbolAbiSignatureBinding] {
        &self.signature_bindings
    }

    /// Returns runtime symbols that still lack complete ABI-signature metadata.
    pub fn missing_bindings(&self) -> &[RuntimeSymbolAbiMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every runtime symbol has ABI-signature metadata.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }

    /// Converts a complete preflight report into ABI-signature metadata.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeSymbolAbiSignaturePlanError::Incomplete`] when any
    /// runtime symbol still lacks ABI-signature metadata.
    pub fn into_abi_signature_plan(
        self,
    ) -> Result<RuntimeSymbolAbiSignaturePlan, RuntimeSymbolAbiSignaturePlanError> {
        let missing_count = self.missing_bindings.len();
        if missing_count == 0 {
            Ok(RuntimeSymbolAbiSignaturePlan::new(self.signature_bindings))
        } else {
            Err(RuntimeSymbolAbiSignaturePlanError::Incomplete {
                missing_count,
                preflight: self,
            })
        }
    }
}

/// An address-free helper runtime symbol ready for future wrapper generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeTargetCandidateBinding {
    symbol_name: String,
    role: RuntimeHelperRole,
}

impl RuntimeSymbolNativeTargetCandidateBinding {
    pub(in crate::runtime::helpers) fn helper(helper_binding: RuntimeHelperBinding) -> Self {
        debug_assert!(helper_binding.rust_callable_binding().is_some());
        Self {
            symbol_name: helper_binding.symbol_name().to_owned(),
            role: helper_binding.role(),
        }
    }

    /// Returns the stable runtime symbol name served by this target candidate.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the helper role covered by this native-target candidate.
    pub const fn helper_role(&self) -> RuntimeHelperRole {
        self.role
    }
}

/// One runtime symbol that cannot yet become a native-target candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolNativeTargetCandidateMissingBinding {
    /// The symbol still lacks ABI-signature metadata.
    MissingAbiSignature(RuntimeSymbolAbiMissingBinding),
    /// A helper has ABI metadata but lacks a process-local Rust callable body.
    MissingHelperCallable {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The helper role reserved by the core runtime ABI.
        role: RuntimeHelperRole,
    },
    /// A callable builtin has ABI metadata but no native wrapper body yet.
    MissingBuiltinWrapper {
        /// The callable builtin ABI metadata that needs a wrapper.
        binding: RuntimeBuiltinCallBinding,
        /// The current blockers for generating that wrapper.
        blockers: &'static [RuntimeBuiltinNativeWrapperBlocker],
    },
}

impl RuntimeSymbolNativeTargetCandidateMissingBinding {
    pub(in crate::runtime::helpers) fn abi_signature(
        binding: RuntimeSymbolAbiMissingBinding,
    ) -> Self {
        Self::MissingAbiSignature(binding)
    }

    pub(in crate::runtime::helpers) fn helper_callable(binding: RuntimeHelperBinding) -> Self {
        Self::MissingHelperCallable {
            symbol_name: binding.symbol_name().to_owned(),
            role: binding.role(),
        }
    }

    pub(in crate::runtime::helpers) fn builtin_wrapper(binding: RuntimeBuiltinCallBinding) -> Self {
        Self::MissingBuiltinWrapper {
            binding,
            blockers: runtime_builtin_native_wrapper_blockers(),
        }
    }

    /// Returns the stable runtime symbol name that is not yet candidate-ready.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::MissingAbiSignature(binding) => binding.symbol_name(),
            Self::MissingHelperCallable { symbol_name, .. } => symbol_name,
            Self::MissingBuiltinWrapper { binding, .. } => binding.symbol_name(),
        }
    }

    /// Returns the ABI-signature gap when candidate readiness is blocked earlier.
    pub const fn missing_abi_signature(&self) -> Option<&RuntimeSymbolAbiMissingBinding> {
        match self {
            Self::MissingAbiSignature(binding) => Some(binding),
            Self::MissingHelperCallable { .. } | Self::MissingBuiltinWrapper { .. } => None,
        }
    }

    /// Returns the helper role when a helper lacks a Rust callable body.
    pub const fn missing_helper_callable_role(&self) -> Option<RuntimeHelperRole> {
        match self {
            Self::MissingHelperCallable { role, .. } => Some(*role),
            Self::MissingAbiSignature(_) | Self::MissingBuiltinWrapper { .. } => None,
        }
    }

    /// Returns builtin call metadata when a callable builtin lacks a wrapper.
    pub const fn missing_builtin_wrapper(&self) -> Option<&RuntimeBuiltinCallBinding> {
        match self {
            Self::MissingBuiltinWrapper { binding, .. } => Some(binding),
            Self::MissingAbiSignature(_) | Self::MissingHelperCallable { .. } => None,
        }
    }

    /// Returns builtin-native-wrapper blockers when a callable builtin lacks a wrapper.
    pub const fn missing_builtin_wrapper_blockers(
        &self,
    ) -> Option<&'static [RuntimeBuiltinNativeWrapperBlocker]> {
        match self {
            Self::MissingBuiltinWrapper { blockers, .. } => Some(*blockers),
            Self::MissingAbiSignature(_) | Self::MissingHelperCallable { .. } => None,
        }
    }
}

/// A blocker preventing callable builtin native-wrapper generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeBuiltinNativeWrapperBlocker {
    /// No callable Rust or C ABI wrapper body exists for builtin symbols.
    MissingWrapperBody,
    /// Native runtime-context decoding has not been bound to builtin dispatch.
    RuntimeContextAbiDecodeUnimplemented,
    /// Native environment-pointer decoding has not been bound to builtin dispatch.
    NativeEnvPointerDecodeUnimplemented,
    /// Native `Value` argument materialization has not been bound to builtin dispatch.
    NativeValueArgumentDecodeUnimplemented,
    /// Native wrappers do not yet enter and leave the evaluator builtin call frame.
    EvaluatorCallFrameBindingUnimplemented,
    /// Native wrappers do not yet register decoded builtin arguments as active roots.
    ActiveArgumentRootRegistrationUnimplemented,
    /// Native wrappers do not yet select and dispatch the safe builtin implementation.
    BuiltinDispatchBindingUnimplemented,
    /// Native wrappers do not yet preserve the builtin argument-forcing contract.
    ArgumentForcingContractBindingUnimplemented,
    /// Native wrappers do not yet transfer evaluator traps/errors instead of returning.
    TrapTransferUnimplemented,
    /// Native wrappers do not yet materialize the by-value `Value` ABI return.
    NativeValueReturnMaterializationUnimplemented,
}

/// The complete set of address-free native-target candidates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeTargetCandidatePlan {
    candidate_bindings: Vec<RuntimeSymbolNativeTargetCandidateBinding>,
}

impl RuntimeSymbolNativeTargetCandidatePlan {
    pub(in crate::runtime::helpers) fn new(
        candidate_bindings: Vec<RuntimeSymbolNativeTargetCandidateBinding>,
    ) -> Self {
        Self { candidate_bindings }
    }

    /// Returns native-target candidates in runtime symbol-manifest projection order.
    pub fn candidate_bindings(&self) -> &[RuntimeSymbolNativeTargetCandidateBinding] {
        &self.candidate_bindings
    }
}

/// A deterministic runtime-symbol report for native target candidate metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeTargetCandidatePreflight {
    candidate_bindings: Vec<RuntimeSymbolNativeTargetCandidateBinding>,
    missing_bindings: Vec<RuntimeSymbolNativeTargetCandidateMissingBinding>,
}

impl RuntimeSymbolNativeTargetCandidatePreflight {
    pub(in crate::runtime::helpers) fn new(
        candidate_bindings: Vec<RuntimeSymbolNativeTargetCandidateBinding>,
        missing_bindings: Vec<RuntimeSymbolNativeTargetCandidateMissingBinding>,
    ) -> Self {
        Self {
            candidate_bindings,
            missing_bindings,
        }
    }

    /// Returns helper target candidates in runtime symbol-manifest projection order.
    pub fn candidate_bindings(&self) -> &[RuntimeSymbolNativeTargetCandidateBinding] {
        &self.candidate_bindings
    }

    /// Returns runtime symbols that still lack native-target candidate readiness.
    pub fn missing_bindings(&self) -> &[RuntimeSymbolNativeTargetCandidateMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every runtime symbol has native-target candidate metadata.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }

    /// Converts a complete preflight report into native-target candidate metadata.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeSymbolNativeTargetCandidatePlanError::Incomplete`] when
    /// any runtime symbol still lacks native-target candidate metadata.
    pub fn into_native_target_candidate_plan(
        self,
    ) -> Result<RuntimeSymbolNativeTargetCandidatePlan, RuntimeSymbolNativeTargetCandidatePlanError>
    {
        let missing_count = self.missing_bindings.len();
        if missing_count == 0 {
            Ok(RuntimeSymbolNativeTargetCandidatePlan::new(
                self.candidate_bindings,
            ))
        } else {
            Err(RuntimeSymbolNativeTargetCandidatePlanError::Incomplete {
                missing_count,
                preflight: self,
            })
        }
    }
}

//! Native-export, rust-callable-preflight, and aggregate [`RuntimeHelperBinding`]
//! families, split from [`super`] (RFC-0007 §2 file-size cap).

use super::*;

/// A runtime symbol with native-export readiness metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeExportBinding {
    symbol_name: String,
    role: RuntimeHelperRole,
    failure_convention: RuntimeHelperFailureConvention,
}

impl RuntimeSymbolNativeExportBinding {
    #[cfg(test)]
    pub(in crate::runtime::helpers) fn new(
        symbol_name: String,
        role: RuntimeHelperRole,
        failure_convention: RuntimeHelperFailureConvention,
    ) -> Self {
        Self {
            symbol_name,
            role,
            failure_convention,
        }
    }

    /// Returns the stable runtime symbol name served by this metadata record.
    pub fn symbol_name(&self) -> &str {
        &self.symbol_name
    }

    /// Returns the helper role covered by this metadata record.
    pub const fn helper_role(&self) -> RuntimeHelperRole {
        self.role
    }

    /// Returns the failure convention required by this metadata record.
    pub const fn failure_convention(&self) -> RuntimeHelperFailureConvention {
        self.failure_convention
    }
}

/// One runtime symbol that cannot yet be exported as a native ABI target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeSymbolNativeExportMissingBinding {
    /// The symbol is blocked before native-target candidate readiness.
    MissingNativeTargetCandidate(RuntimeSymbolNativeTargetCandidateMissingBinding),
    /// A helper candidate still lacks an exported C ABI wrapper.
    MissingExportedCAbiWrapper {
        /// The stable runtime symbol name.
        symbol_name: String,
        /// The helper role reserved by the core runtime ABI.
        role: RuntimeHelperRole,
        /// The native failure convention the wrapper must implement.
        failure_convention: RuntimeHelperFailureConvention,
        /// Allocation-specific blockers when this wrapper serves `aos_alloc_*`.
        allocation_blockers: &'static [RuntimeAllocationNativeExportBlocker],
        /// Call-control-specific blockers when this wrapper serves `aos_apply`.
        call_control_blockers: &'static [RuntimeApplyNativeExportBlocker],
        /// Attrset-access-specific blockers when this wrapper serves an attr helper.
        attrset_access_blockers: &'static [RuntimeAttrAccessNativeExportBlocker],
        /// Environment-access-specific blockers when this wrapper serves `aos_env_get`.
        env_access_blockers: &'static [RuntimeEnvAccessNativeExportBlocker],
        /// Forcing-specific blockers when this wrapper serves a forcing helper.
        forcing_blockers: &'static [RuntimeForcingNativeExportBlocker],
        /// Write-barrier-specific blockers when this wrapper serves `aos_gc_write_barrier`.
        write_barrier_blockers: &'static [RuntimeWriteBarrierNativeExportBlocker],
    },
}

impl RuntimeSymbolNativeExportMissingBinding {
    pub(in crate::runtime::helpers) fn native_target_candidate(
        binding: RuntimeSymbolNativeTargetCandidateMissingBinding,
    ) -> Self {
        Self::MissingNativeTargetCandidate(binding)
    }

    pub(in crate::runtime::helpers) fn exported_c_abi_wrapper(
        symbol_name: String,
        role: RuntimeHelperRole,
        failure_convention: RuntimeHelperFailureConvention,
        allocation_blockers: &'static [RuntimeAllocationNativeExportBlocker],
        call_control_blockers: &'static [RuntimeApplyNativeExportBlocker],
        attrset_access_blockers: &'static [RuntimeAttrAccessNativeExportBlocker],
        env_access_blockers: &'static [RuntimeEnvAccessNativeExportBlocker],
        forcing_blockers: &'static [RuntimeForcingNativeExportBlocker],
        write_barrier_blockers: &'static [RuntimeWriteBarrierNativeExportBlocker],
    ) -> Self {
        Self::MissingExportedCAbiWrapper {
            symbol_name,
            role,
            failure_convention,
            allocation_blockers,
            call_control_blockers,
            attrset_access_blockers,
            env_access_blockers,
            forcing_blockers,
            write_barrier_blockers,
        }
    }

    /// Returns the stable runtime symbol name that is not yet export-ready.
    pub fn symbol_name(&self) -> &str {
        match self {
            Self::MissingNativeTargetCandidate(binding) => binding.symbol_name(),
            Self::MissingExportedCAbiWrapper { symbol_name, .. } => symbol_name,
        }
    }

    /// Returns the earlier native-target candidate gap, when present.
    pub const fn missing_native_target_candidate(
        &self,
    ) -> Option<&RuntimeSymbolNativeTargetCandidateMissingBinding> {
        match self {
            Self::MissingNativeTargetCandidate(binding) => Some(binding),
            Self::MissingExportedCAbiWrapper { .. } => None,
        }
    }

    /// Returns the helper role when the missing piece is an exported C ABI wrapper.
    pub const fn missing_exported_c_abi_wrapper_role(&self) -> Option<RuntimeHelperRole> {
        match self {
            Self::MissingExportedCAbiWrapper { role, .. } => Some(*role),
            Self::MissingNativeTargetCandidate(_) => None,
        }
    }

    /// Returns the failure convention required by the missing C ABI wrapper.
    pub const fn missing_exported_c_abi_failure_convention(
        &self,
    ) -> Option<RuntimeHelperFailureConvention> {
        match self {
            Self::MissingExportedCAbiWrapper {
                failure_convention, ..
            } => Some(*failure_convention),
            Self::MissingNativeTargetCandidate(_) => None,
        }
    }

    /// Returns allocation-specific blockers for a missing `aos_alloc_*` C ABI wrapper.
    pub fn missing_exported_allocation_blockers(
        &self,
    ) -> Option<&'static [RuntimeAllocationNativeExportBlocker]> {
        match self {
            Self::MissingExportedCAbiWrapper {
                allocation_blockers,
                ..
            } if !allocation_blockers.is_empty() => Some(*allocation_blockers),
            Self::MissingExportedCAbiWrapper { .. } | Self::MissingNativeTargetCandidate(_) => None,
        }
    }

    /// Returns call-control-specific blockers for a missing `aos_apply` C ABI wrapper.
    pub fn missing_exported_call_control_blockers(
        &self,
    ) -> Option<&'static [RuntimeApplyNativeExportBlocker]> {
        match self {
            Self::MissingExportedCAbiWrapper {
                call_control_blockers,
                ..
            } if !call_control_blockers.is_empty() => Some(*call_control_blockers),
            Self::MissingExportedCAbiWrapper { .. } | Self::MissingNativeTargetCandidate(_) => None,
        }
    }

    /// Returns attrset-access-specific blockers for a missing attr helper wrapper.
    pub fn missing_exported_attrset_access_blockers(
        &self,
    ) -> Option<&'static [RuntimeAttrAccessNativeExportBlocker]> {
        match self {
            Self::MissingExportedCAbiWrapper {
                attrset_access_blockers,
                ..
            } if !attrset_access_blockers.is_empty() => Some(*attrset_access_blockers),
            Self::MissingExportedCAbiWrapper { .. } | Self::MissingNativeTargetCandidate(_) => None,
        }
    }

    /// Returns environment-access-specific blockers for a missing `aos_env_get` wrapper.
    pub fn missing_exported_env_access_blockers(
        &self,
    ) -> Option<&'static [RuntimeEnvAccessNativeExportBlocker]> {
        match self {
            Self::MissingExportedCAbiWrapper {
                env_access_blockers,
                ..
            } if !env_access_blockers.is_empty() => Some(*env_access_blockers),
            Self::MissingExportedCAbiWrapper { .. } | Self::MissingNativeTargetCandidate(_) => None,
        }
    }

    /// Returns forcing-specific blockers for a missing forcing-helper C ABI wrapper.
    pub fn missing_exported_forcing_blockers(
        &self,
    ) -> Option<&'static [RuntimeForcingNativeExportBlocker]> {
        match self {
            Self::MissingExportedCAbiWrapper {
                forcing_blockers, ..
            } if !forcing_blockers.is_empty() => Some(*forcing_blockers),
            Self::MissingExportedCAbiWrapper { .. } | Self::MissingNativeTargetCandidate(_) => None,
        }
    }

    /// Returns write-barrier-specific blockers for a missing `aos_gc_write_barrier` wrapper.
    pub fn missing_exported_write_barrier_blockers(
        &self,
    ) -> Option<&'static [RuntimeWriteBarrierNativeExportBlocker]> {
        match self {
            Self::MissingExportedCAbiWrapper {
                write_barrier_blockers,
                ..
            } if !write_barrier_blockers.is_empty() => Some(*write_barrier_blockers),
            Self::MissingExportedCAbiWrapper { .. } | Self::MissingNativeTargetCandidate(_) => None,
        }
    }
}

/// The complete set of runtime-symbol native-export metadata records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeExportPlan {
    export_bindings: Vec<RuntimeSymbolNativeExportBinding>,
}

impl RuntimeSymbolNativeExportPlan {
    pub(in crate::runtime::helpers) fn new(
        export_bindings: Vec<RuntimeSymbolNativeExportBinding>,
    ) -> Self {
        Self { export_bindings }
    }

    /// Returns native-export metadata records in runtime symbol-manifest order.
    pub fn export_bindings(&self) -> &[RuntimeSymbolNativeExportBinding] {
        &self.export_bindings
    }
}

/// A deterministic runtime-symbol report for exported native ABI readiness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolNativeExportPreflight {
    export_bindings: Vec<RuntimeSymbolNativeExportBinding>,
    missing_bindings: Vec<RuntimeSymbolNativeExportMissingBinding>,
}

impl RuntimeSymbolNativeExportPreflight {
    pub(in crate::runtime::helpers) fn new(
        export_bindings: Vec<RuntimeSymbolNativeExportBinding>,
        missing_bindings: Vec<RuntimeSymbolNativeExportMissingBinding>,
    ) -> Self {
        Self {
            export_bindings,
            missing_bindings,
        }
    }

    /// Returns native-export metadata records in runtime symbol-manifest order.
    pub fn export_bindings(&self) -> &[RuntimeSymbolNativeExportBinding] {
        &self.export_bindings
    }

    /// Returns runtime symbols that still lack native-export readiness.
    pub fn missing_bindings(&self) -> &[RuntimeSymbolNativeExportMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every runtime symbol has exported native ABI metadata.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }

    /// Converts a complete preflight report into native-export metadata.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeSymbolNativeExportPlanError::Incomplete`] when any
    /// runtime symbol still lacks exported native ABI metadata.
    pub fn into_native_export_plan(
        self,
    ) -> Result<RuntimeSymbolNativeExportPlan, RuntimeSymbolNativeExportPlanError> {
        let missing_count = self.missing_bindings.len();
        if missing_count == 0 {
            Ok(RuntimeSymbolNativeExportPlan::new(self.export_bindings))
        } else {
            Err(RuntimeSymbolNativeExportPlanError::Incomplete {
                missing_count,
                preflight: self,
            })
        }
    }
}

/// A deterministic runtime-symbol report for callable Rust storage wrappers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSymbolRustCallablePreflight {
    helper_callables: Vec<RuntimeHelperRustCallableBinding>,
    missing_bindings: Vec<RuntimeSymbolMissingBinding>,
}

impl RuntimeSymbolRustCallablePreflight {
    pub(in crate::runtime::helpers) fn new(
        helper_callables: Vec<RuntimeHelperRustCallableBinding>,
        missing_bindings: Vec<RuntimeSymbolMissingBinding>,
    ) -> Self {
        Self {
            helper_callables,
            missing_bindings,
        }
    }

    /// Returns callable helper metadata in runtime symbol-manifest order.
    pub fn helper_callables(&self) -> &[RuntimeHelperRustCallableBinding] {
        &self.helper_callables
    }

    /// Returns runtime symbols that still lack a complete registration binding.
    pub fn missing_bindings(&self) -> &[RuntimeSymbolMissingBinding] {
        &self.missing_bindings
    }

    /// Returns true when every runtime symbol has a callable registration binding.
    pub fn is_complete(&self) -> bool {
        self.missing_bindings.is_empty()
    }
}

/// The native failure behavior promised by a runtime helper binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeHelperFailureConvention {
    /// The helper returns only on success and transfers failures to evaluator
    /// trap/error machinery instead of returning a null pointer or sentinel.
    TrapToEvaluator,
}

/// A safe ABI binding for one frozen runtime helper symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeHelperBinding {
    /// A heap allocation helper routed through `runtime::alloc`.
    Allocation(RuntimeAllocationAbiSignature),
    /// A call-control helper routed through `runtime::apply`.
    CallControl(RuntimeApplyAbiSignature),
    /// An attrset-access helper routed through `runtime::attr`.
    AttrsetAccess(RuntimeAttrAccessAbiSignature),
    /// An environment-access helper routed through `runtime::env`.
    EnvironmentAccess(RuntimeEnvAccessAbiSignature),
    /// A forcing helper routed through `runtime::forcing`.
    Forcing(RuntimeForcingAbiSignature),
    /// A write-barrier helper routed through `runtime::barrier`.
    WriteBarrier(RuntimeWriteBarrierAbiSignature),
}

impl RuntimeHelperBinding {
    /// Returns the stable helper symbol name.
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::Allocation(signature) => signature.symbol_name(),
            Self::CallControl(signature) => signature.symbol_name(),
            Self::AttrsetAccess(signature) => signature.symbol_name(),
            Self::EnvironmentAccess(signature) => signature.symbol_name(),
            Self::Forcing(signature) => signature.symbol_name(),
            Self::WriteBarrier(signature) => signature.symbol_name(),
        }
    }

    /// Returns the core helper role served by this binding.
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

    /// Returns the native failure convention for this helper binding.
    pub const fn failure_convention(self) -> RuntimeHelperFailureConvention {
        match self {
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => RuntimeHelperFailureConvention::TrapToEvaluator,
        }
    }

    /// Returns the callable Rust storage-wrapper binding for this helper, if any.
    pub fn rust_callable_binding(self) -> Option<RuntimeHelperRustCallableBinding> {
        match self {
            Self::Allocation(signature) => Some(RuntimeHelperRustCallableBinding::Allocation(
                signature.entrypoint().rust_callable_binding(),
            )),
            Self::CallControl(signature) => Some(RuntimeHelperRustCallableBinding::CallControl(
                signature.entrypoint().rust_callable_binding(),
            )),
            Self::AttrsetAccess(signature) => {
                Some(RuntimeHelperRustCallableBinding::AttrsetAccess(
                    signature.entrypoint().rust_callable_binding(),
                ))
            }
            Self::EnvironmentAccess(signature) => {
                Some(RuntimeHelperRustCallableBinding::EnvironmentAccess(
                    signature.entrypoint().rust_callable_binding(),
                ))
            }
            Self::Forcing(signature) => Some(RuntimeHelperRustCallableBinding::Forcing(
                signature.entrypoint().rust_callable_binding(),
            )),
            Self::WriteBarrier(signature) => Some(RuntimeHelperRustCallableBinding::WriteBarrier(
                signature.entrypoint().rust_callable_binding(),
            )),
        }
    }

    /// Returns the binding for a frozen runtime helper symbol name.
    pub fn from_symbol_name(symbol_name: &str) -> Option<Self> {
        RuntimeAllocationAbiSignature::from_symbol_name(symbol_name)
            .map(Self::Allocation)
            .or_else(|| {
                RuntimeApplyAbiSignature::from_symbol_name(symbol_name).map(Self::CallControl)
            })
            .or_else(|| {
                RuntimeAttrAccessAbiSignature::from_symbol_name(symbol_name)
                    .map(Self::AttrsetAccess)
            })
            .or_else(|| {
                RuntimeEnvAccessAbiSignature::from_symbol_name(symbol_name)
                    .map(Self::EnvironmentAccess)
            })
            .or_else(|| {
                RuntimeForcingAbiSignature::from_symbol_name(symbol_name).map(Self::Forcing)
            })
            .or_else(|| {
                RuntimeWriteBarrierAbiSignature::from_symbol_name(symbol_name)
                    .map(Self::WriteBarrier)
            })
    }

    /// Returns the allocation ABI signature when this binding serves allocation.
    pub const fn allocation_signature(self) -> Option<RuntimeAllocationAbiSignature> {
        match self {
            Self::Allocation(signature) => Some(signature),
            Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns allocation-native-export blockers for allocation helpers.
    pub const fn allocation_native_export_blockers(
        self,
    ) -> &'static [RuntimeAllocationNativeExportBlocker] {
        match self {
            Self::Allocation(signature) => signature.entrypoint().native_export_blockers(),
            Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => &[],
        }
    }

    /// Returns the apply ABI signature when this binding serves call control.
    pub const fn call_control_signature(self) -> Option<RuntimeApplyAbiSignature> {
        match self {
            Self::CallControl(signature) => Some(signature),
            Self::Allocation(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns apply-native-export blockers for call-control helpers.
    pub const fn call_control_native_export_blockers(
        self,
    ) -> &'static [RuntimeApplyNativeExportBlocker] {
        match self {
            Self::CallControl(signature) => signature.entrypoint().native_export_blockers(),
            Self::Allocation(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => &[],
        }
    }

    /// Returns the attrset-access ABI signature when this binding serves attrset access.
    pub const fn attrset_access_signature(self) -> Option<RuntimeAttrAccessAbiSignature> {
        match self {
            Self::AttrsetAccess(signature) => Some(signature),
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns attrset-access-native-export blockers for attrset-access helpers.
    pub const fn attrset_access_native_export_blockers(
        self,
    ) -> &'static [RuntimeAttrAccessNativeExportBlocker] {
        match self {
            Self::AttrsetAccess(signature) => signature.entrypoint().native_export_blockers(),
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => &[],
        }
    }

    /// Returns the environment-access ABI signature when this binding serves environment access.
    pub const fn env_access_signature(self) -> Option<RuntimeEnvAccessAbiSignature> {
        match self {
            Self::EnvironmentAccess(signature) => Some(signature),
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns environment-access-native-export blockers for environment helpers.
    pub const fn env_access_native_export_blockers(
        self,
    ) -> &'static [RuntimeEnvAccessNativeExportBlocker] {
        match self {
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::Forcing(_)
            | Self::WriteBarrier(_) => &[],
            Self::EnvironmentAccess(signature) => signature.entrypoint().native_export_blockers(),
        }
    }

    /// Returns the forcing ABI signature when this binding serves forcing control.
    pub const fn forcing_signature(self) -> Option<RuntimeForcingAbiSignature> {
        match self {
            Self::Forcing(signature) => Some(signature),
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::WriteBarrier(_) => None,
        }
    }

    /// Returns forcing-native-export blockers for forcing helpers.
    pub const fn forcing_native_export_blockers(
        self,
    ) -> &'static [RuntimeForcingNativeExportBlocker] {
        match self {
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::WriteBarrier(_) => &[],
            Self::Forcing(signature) => signature.entrypoint().native_export_blockers(),
        }
    }

    /// Returns the write-barrier ABI signature when this binding serves a barrier.
    pub const fn write_barrier_signature(self) -> Option<RuntimeWriteBarrierAbiSignature> {
        match self {
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_) => None,
            Self::WriteBarrier(signature) => Some(signature),
        }
    }

    /// Returns write-barrier-native-export blockers for write-barrier helpers.
    pub const fn write_barrier_native_export_blockers(
        self,
    ) -> &'static [RuntimeWriteBarrierNativeExportBlocker] {
        match self {
            Self::Allocation(_)
            | Self::CallControl(_)
            | Self::AttrsetAccess(_)
            | Self::EnvironmentAccess(_)
            | Self::Forcing(_) => &[],
            Self::WriteBarrier(signature) => signature.entrypoint().native_export_blockers(),
        }
    }

    /// Returns the core runtime-call signature for this helper binding.
    pub fn core_call_signature(self) -> Option<RuntimeCallSignature> {
        runtime_helper_call_signature(self.symbol_name())
    }
}

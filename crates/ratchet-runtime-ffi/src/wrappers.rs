//! Unified native-wrapper manifest for runtime FFI helpers.
//!
//! Each helper-family module owns its frozen C ABI body and family-specific
//! blocker list. This module projects those bindings into the core runtime
//! symbol order so future native registration can consume one manifest instead
//! of stitching allocation, call-control, attrset-access, environment-access,
//! forcing, and write-barrier wrappers together by symbol text.

use std::{collections::BTreeMap, ffi::c_void};

use ratchet_oracle::compile::{
    RuntimeHelperRole, RuntimeSymbolKind, RuntimeSymbolNameError, runtime_symbol_manifest,
};
use ratchet_oracle::runtime::{
    alloc::RuntimeAllocationNativeExportBlocker, apply::RuntimeApplyNativeExportBlocker,
    attr::RuntimeAttrAccessNativeExportBlocker, barrier::RuntimeWriteBarrierNativeExportBlocker,
    env::RuntimeEnvAccessNativeExportBlocker, forcing::RuntimeForcingNativeExportBlocker,
};

use crate::alloc::{
    RuntimeAllocationNativeWrapperBinding, runtime_allocation_native_wrapper_bindings,
};
use crate::apply::{RuntimeApplyNativeWrapperBinding, runtime_apply_native_wrapper_bindings};
use crate::attr::{
    RuntimeAttrAccessNativeWrapperBinding, runtime_attr_access_native_wrapper_bindings,
};
use crate::barrier::{
    RuntimeWriteBarrierNativeWrapperBinding, runtime_write_barrier_native_wrapper_bindings,
};
use crate::env::{
    RuntimeEnvAccessNativeWrapperBinding, runtime_env_access_native_wrapper_bindings,
};
use crate::force::{RuntimeForcingNativeWrapperBinding, runtime_forcing_native_wrapper_bindings};

/// Result returned when building the runtime-FFI native-wrapper manifest.
pub type RuntimeNativeWrapperManifestResult =
    Result<Vec<RuntimeNativeWrapperBinding>, RuntimeSymbolNameError>;

/// Returns native-wrapper bindings in core runtime-symbol order.
///
/// The returned bindings are process-local C ABI wrapper addresses. They are
/// not final JIT registrations: each binding still carries its family-specific
/// remaining wrapper-local export blockers.
///
/// # Errors
///
/// Returns [`RuntimeSymbolNameError`] if the core runtime symbol manifest cannot
/// be built.
pub fn runtime_native_wrapper_bindings() -> RuntimeNativeWrapperManifestResult {
    let wrappers_by_symbol = native_wrappers_by_symbol();
    let mut wrappers = Vec::new();

    for entry in runtime_symbol_manifest()? {
        if !matches!(entry.kind(), RuntimeSymbolKind::Helper(_)) {
            continue;
        }
        if let Some(wrapper) = wrappers_by_symbol.get(entry.name()).copied() {
            wrappers.push(wrapper);
        }
    }

    Ok(wrappers)
}

fn native_wrappers_by_symbol() -> BTreeMap<&'static str, RuntimeNativeWrapperBinding> {
    let mut wrappers = BTreeMap::new();

    for binding in runtime_allocation_native_wrapper_bindings() {
        wrappers.insert(
            binding.symbol_name(),
            RuntimeNativeWrapperBinding::Allocation(binding),
        );
    }
    for binding in runtime_apply_native_wrapper_bindings() {
        wrappers.insert(
            binding.symbol_name(),
            RuntimeNativeWrapperBinding::CallControl(binding),
        );
    }
    for binding in runtime_attr_access_native_wrapper_bindings() {
        wrappers.insert(
            binding.symbol_name(),
            RuntimeNativeWrapperBinding::AttrsetAccess(binding),
        );
    }
    for binding in runtime_env_access_native_wrapper_bindings() {
        wrappers.insert(
            binding.symbol_name(),
            RuntimeNativeWrapperBinding::EnvironmentAccess(binding),
        );
    }
    for binding in runtime_forcing_native_wrapper_bindings() {
        wrappers.insert(
            binding.symbol_name(),
            RuntimeNativeWrapperBinding::Forcing(binding),
        );
    }
    for binding in runtime_write_barrier_native_wrapper_bindings() {
        wrappers.insert(
            binding.symbol_name(),
            RuntimeNativeWrapperBinding::WriteBarrier(binding),
        );
    }

    wrappers
}

/// Process-local address metadata for one native wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeNativeWrapperAddress {
    ptr: *mut c_void,
}

impl RuntimeNativeWrapperAddress {
    const fn new(ptr: *mut c_void) -> Self {
        Self { ptr }
    }

    /// Returns the process-local wrapper address.
    pub const fn as_ptr(self) -> *mut c_void {
        self.ptr
    }

    /// Returns true when the wrapper address is non-null.
    pub const fn is_non_null(self) -> bool {
        !self.ptr.is_null()
    }
}

/// Native-wrapper metadata for one runtime helper family.
#[derive(Clone, Copy, Debug)]
pub enum RuntimeNativeWrapperBinding {
    /// A heap allocation helper wrapper.
    Allocation(RuntimeAllocationNativeWrapperBinding),
    /// The call-control helper wrapper.
    CallControl(RuntimeApplyNativeWrapperBinding),
    /// An attrset-access helper wrapper.
    AttrsetAccess(RuntimeAttrAccessNativeWrapperBinding),
    /// The environment-access helper wrapper.
    EnvironmentAccess(RuntimeEnvAccessNativeWrapperBinding),
    /// A forcing helper wrapper.
    Forcing(RuntimeForcingNativeWrapperBinding),
    /// The thunk-resolution write-barrier helper wrapper.
    WriteBarrier(RuntimeWriteBarrierNativeWrapperBinding),
}

impl RuntimeNativeWrapperBinding {
    /// Returns the stable runtime symbol name served by this wrapper.
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

    /// Returns the core helper role served by this wrapper.
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

    /// Returns the process-local wrapper address.
    pub const fn address(self) -> RuntimeNativeWrapperAddress {
        let ptr = match self {
            Self::Allocation(binding) => binding.address().as_ptr(),
            Self::CallControl(binding) => binding.address().as_ptr(),
            Self::AttrsetAccess(binding) => binding.address().as_ptr(),
            Self::EnvironmentAccess(binding) => binding.address().as_ptr(),
            Self::Forcing(binding) => binding.address().as_ptr(),
            Self::WriteBarrier(binding) => binding.address().as_ptr(),
        };
        RuntimeNativeWrapperAddress::new(ptr)
    }

    /// Returns family-specific wrapper-local blockers still tracked by the wrapper.
    ///
    /// These blockers are provenance for process-local runtime-FFI wrapper
    /// bodies. The oracle native-export gates remain authoritative for final
    /// registration readiness.
    pub const fn remaining_export_blockers(self) -> RuntimeNativeWrapperBlockers {
        match self {
            Self::Allocation(binding) => {
                RuntimeNativeWrapperBlockers::Allocation(binding.remaining_export_blockers())
            }
            Self::CallControl(binding) => {
                RuntimeNativeWrapperBlockers::CallControl(binding.remaining_export_blockers())
            }
            Self::AttrsetAccess(binding) => {
                RuntimeNativeWrapperBlockers::AttrsetAccess(binding.remaining_export_blockers())
            }
            Self::EnvironmentAccess(binding) => {
                RuntimeNativeWrapperBlockers::EnvironmentAccess(binding.remaining_export_blockers())
            }
            Self::Forcing(binding) => {
                RuntimeNativeWrapperBlockers::Forcing(binding.remaining_export_blockers())
            }
            Self::WriteBarrier(binding) => {
                RuntimeNativeWrapperBlockers::WriteBarrier(binding.remaining_export_blockers())
            }
        }
    }

    /// Returns true when the wrapper has no remaining export blockers.
    pub const fn is_export_ready(self) -> bool {
        self.remaining_export_blockers().is_empty()
    }
}

impl PartialEq for RuntimeNativeWrapperBinding {
    fn eq(&self, other: &Self) -> bool {
        self.symbol_name() == other.symbol_name()
            && self.role() == other.role()
            && self.address() == other.address()
            && self.remaining_export_blockers() == other.remaining_export_blockers()
    }
}

impl Eq for RuntimeNativeWrapperBinding {}

/// Family-specific wrapper-local blockers tracked by runtime-FFI wrappers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeNativeWrapperBlockers {
    /// Allocation helper export blockers.
    Allocation(&'static [RuntimeAllocationNativeExportBlocker]),
    /// Call-control helper export blockers.
    CallControl(&'static [RuntimeApplyNativeExportBlocker]),
    /// Attrset-access helper export blockers.
    AttrsetAccess(&'static [RuntimeAttrAccessNativeExportBlocker]),
    /// Environment-access helper export blockers.
    EnvironmentAccess(&'static [RuntimeEnvAccessNativeExportBlocker]),
    /// Forcing helper export blockers.
    Forcing(&'static [RuntimeForcingNativeExportBlocker]),
    /// Write-barrier helper export blockers.
    WriteBarrier(&'static [RuntimeWriteBarrierNativeExportBlocker]),
}

impl RuntimeNativeWrapperBlockers {
    /// Returns the number of remaining blockers.
    pub const fn len(self) -> usize {
        match self {
            Self::Allocation(blockers) => blockers.len(),
            Self::CallControl(blockers) => blockers.len(),
            Self::AttrsetAccess(blockers) => blockers.len(),
            Self::EnvironmentAccess(blockers) => blockers.len(),
            Self::Forcing(blockers) => blockers.len(),
            Self::WriteBarrier(blockers) => blockers.len(),
        }
    }

    /// Returns whether there are no remaining blockers.
    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Returns true when this blocker list still carries the final-export gate.
    pub fn contains_final_exported_wrapper_blocker(self) -> bool {
        match self {
            Self::Allocation(blockers) => blockers
                .contains(&RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper),
            Self::CallControl(blockers) => {
                blockers.contains(&RuntimeApplyNativeExportBlocker::MissingFinalExportedWrapper)
            }
            Self::AttrsetAccess(blockers) => blockers
                .contains(&RuntimeAttrAccessNativeExportBlocker::MissingFinalExportedWrapper),
            Self::EnvironmentAccess(blockers) => {
                blockers.contains(&RuntimeEnvAccessNativeExportBlocker::MissingFinalExportedWrapper)
            }
            Self::Forcing(blockers) => {
                blockers.contains(&RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper)
            }
            Self::WriteBarrier(blockers) => blockers
                .contains(&RuntimeWriteBarrierNativeExportBlocker::MissingFinalExportedWrapper),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn native_wrapper_manifest_preserves_runtime_symbol_order() {
        let bindings = runtime_native_wrapper_bindings().expect("wrapper manifest builds");
        let wrapper_symbols = bindings
            .iter()
            .copied()
            .map(RuntimeNativeWrapperBinding::symbol_name)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let wrapped_symbol_set = native_wrappers_by_symbol()
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let expected_symbols = runtime_symbol_manifest()
            .expect("runtime symbol manifest builds")
            .into_iter()
            .filter(|entry| matches!(entry.kind(), RuntimeSymbolKind::Helper(_)))
            .map(|entry| entry.name().to_owned())
            .filter(|symbol| wrapped_symbol_set.contains(symbol.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(wrapper_symbols, expected_symbols);
    }

    #[test]
    fn native_wrapper_manifest_covers_family_inventories() {
        let bindings = runtime_native_wrapper_bindings().expect("wrapper manifest builds");
        let manifest_symbols = bindings
            .iter()
            .copied()
            .map(RuntimeNativeWrapperBinding::symbol_name)
            .collect::<BTreeSet<_>>();
        let family_symbols = family_wrapper_symbols();
        let family_symbol_set = family_symbols.iter().copied().collect::<BTreeSet<_>>();

        assert_eq!(family_symbols.len(), family_symbol_set.len());
        assert_eq!(bindings.len(), family_symbols.len());
        assert_eq!(manifest_symbols, family_symbol_set);
    }

    #[test]
    fn native_wrapper_manifest_exposes_addresses_roles_and_blockers() {
        let bindings = runtime_native_wrapper_bindings().expect("wrapper manifest builds");
        let core_helper_roles = core_helper_roles_by_symbol();

        assert!(bindings.iter().copied().all(|binding| {
            binding.address().is_non_null()
                && !binding.is_export_ready()
                && !binding.remaining_export_blockers().is_empty()
                && !binding
                    .remaining_export_blockers()
                    .contains_final_exported_wrapper_blocker()
        }));
        assert!(bindings.iter().copied().all(|binding| {
            core_helper_roles
                .get(binding.symbol_name())
                .copied()
                .is_some_and(|role| role == binding.role())
        }));
        assert!(bindings.iter().copied().any(|binding| {
            binding.symbol_name() == "aos_gc_write_barrier"
                && binding.role() == RuntimeHelperRole::WriteBarrier
                && matches!(
                    binding.remaining_export_blockers(),
                    RuntimeNativeWrapperBlockers::WriteBarrier(blockers)
                        if blockers.contains(
                            &RuntimeWriteBarrierNativeExportBlocker::BarrierDispatchUnimplemented
                        )
                )
        }));
        assert!(bindings.iter().copied().any(|binding| {
            binding.symbol_name() == "aos_env_get"
                && binding.role() == RuntimeHelperRole::EnvironmentAccess
                && binding.remaining_export_blockers().len() == 1
        }));
    }

    fn family_wrapper_symbols() -> Vec<&'static str> {
        runtime_allocation_native_wrapper_bindings()
            .iter()
            .copied()
            .map(RuntimeAllocationNativeWrapperBinding::symbol_name)
            .chain(
                runtime_apply_native_wrapper_bindings()
                    .iter()
                    .copied()
                    .map(RuntimeApplyNativeWrapperBinding::symbol_name),
            )
            .chain(
                runtime_attr_access_native_wrapper_bindings()
                    .iter()
                    .copied()
                    .map(RuntimeAttrAccessNativeWrapperBinding::symbol_name),
            )
            .chain(
                runtime_env_access_native_wrapper_bindings()
                    .iter()
                    .copied()
                    .map(RuntimeEnvAccessNativeWrapperBinding::symbol_name),
            )
            .chain(
                runtime_forcing_native_wrapper_bindings()
                    .iter()
                    .copied()
                    .map(RuntimeForcingNativeWrapperBinding::symbol_name),
            )
            .chain(
                runtime_write_barrier_native_wrapper_bindings()
                    .iter()
                    .copied()
                    .map(RuntimeWriteBarrierNativeWrapperBinding::symbol_name),
            )
            .collect()
    }

    fn core_helper_roles_by_symbol() -> BTreeMap<String, RuntimeHelperRole> {
        runtime_symbol_manifest()
            .expect("core manifest builds")
            .into_iter()
            .filter_map(|entry| match entry.kind() {
                RuntimeSymbolKind::Helper(role) => Some((entry.name().to_owned(), role)),
                RuntimeSymbolKind::Builtin => None,
            })
            .collect()
    }
}

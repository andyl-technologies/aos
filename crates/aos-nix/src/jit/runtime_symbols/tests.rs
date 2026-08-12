use ratchet_core::{RuntimeHelperRole, RuntimeSymbolKind};
use ratchet_jit::{
    JitRuntimeSymbolRegistrationGap, jit_runtime_symbol_registration_preflight_with_candidates,
};
use ratchet_oracle::runtime::{
    alloc::RuntimeAllocationEntryPoint, apply::RuntimeApplyEntryPoint,
    attr::RuntimeAttrAccessEntryPoint, barrier::RuntimeWriteBarrierEntryPoint,
    forcing::RuntimeForcingEntryPoint, helpers::runtime_symbol_rust_callable_preflight,
};
use ratchet_runtime_ffi::wrappers::runtime_native_wrapper_bindings;

#[allow(unused_imports)]
use super::candidates::{
    helper_callable_address, jit_address_candidate_for_helper_binding,
    jit_address_candidate_for_helper_callable,
    jit_address_candidate_for_runtime_ffi_native_wrapper, runtime_native_wrappers_by_symbol,
};
use super::*;

const EXPECTED_ALLOCATION_SYMBOLS: &[&str] = &[
    "aos_alloc_attrs",
    "aos_alloc_cons",
    "aos_alloc_lambda",
    "aos_alloc_list",
    "aos_alloc_raw",
    "aos_alloc_string",
    "aos_alloc_thunk",
];

const EXPECTED_ENV_ACCESS_SYMBOLS: &[&str] = &["aos_env_get"];
const EXPECTED_CALL_CONTROL_SYMBOLS: &[&str] = &["aos_apply"];
const EXPECTED_RUNTIME_FFI_ALLOCATION_SYMBOLS: &[&str] = EXPECTED_ALLOCATION_SYMBOLS;
const EXPECTED_RUST_CALLABLE_ALLOCATION_SYMBOLS: &[&str] = &[];
const EXPECTED_RUNTIME_FFI_CALL_CONTROL_SYMBOLS: &[&str] = &["aos_apply"];
const EXPECTED_ATTRSET_ACCESS_SYMBOLS: &[&str] = &["aos_has_attr", "aos_select_ic", "aos_update"];
const EXPECTED_RUNTIME_FFI_ATTRSET_ACCESS_SYMBOLS: &[&str] =
    &["aos_has_attr", "aos_select_ic", "aos_update"];
const EXPECTED_RUST_CALLABLE_ATTRSET_ACCESS_SYMBOLS: &[&str] = &[];
const EXPECTED_FORCE_SYMBOLS: &[&str] = &["aos_blackhole_check", "aos_force", "aos_force_deep"];
const EXPECTED_RUNTIME_FFI_FORCE_SYMBOLS: &[&str] =
    &["aos_blackhole_check", "aos_force", "aos_force_deep"];
const EXPECTED_RUST_CALLABLE_FORCE_SYMBOLS: &[&str] = &[];
const EXPECTED_WRITE_BARRIER_SYMBOLS: &[&str] = &["aos_gc_write_barrier"];
const EXPECTED_RUNTIME_FFI_WRITE_BARRIER_SYMBOLS: &[&str] = &["aos_gc_write_barrier"];
const EXPECTED_RUNTIME_FFI_SYMBOLS: &[&str] = &[
    "aos_alloc_attrs",
    "aos_alloc_cons",
    "aos_alloc_lambda",
    "aos_alloc_list",
    "aos_alloc_raw",
    "aos_alloc_string",
    "aos_alloc_thunk",
    "aos_apply",
    "aos_blackhole_check",
    "aos_env_get",
    "aos_force",
    "aos_force_deep",
    "aos_gc_write_barrier",
    "aos_has_attr",
    "aos_select_ic",
    "aos_update",
];

fn allocation_native_wrapper_address(symbol_name: &str) -> usize {
    runtime_native_wrapper_address(symbol_name)
}

fn runtime_native_wrapper_symbols() -> Vec<&'static str> {
    runtime_native_wrapper_bindings()
        .expect("runtime FFI native-wrapper manifest builds")
        .into_iter()
        .map(|binding| binding.symbol_name())
        .collect()
}

fn runtime_native_wrapper_address(symbol_name: &str) -> usize {
    runtime_native_wrapper_bindings()
        .expect("runtime FFI native-wrapper manifest builds")
        .into_iter()
        .find(|binding| binding.symbol_name() == symbol_name)
        .expect("runtime FFI native wrapper exists")
        .address()
        .as_ptr() as usize
}

fn allocation_rust_callable_address(symbol_name: &str) -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == symbol_name)
        .expect("oracle allocation Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::Allocation(binding) => {
            binding.address().as_ptr() as usize
        }
        _ => panic!("{symbol_name} is an allocation helper"),
    }
}

fn env_native_wrapper_address() -> usize {
    runtime_native_wrapper_address("aos_env_get")
}

fn apply_native_wrapper_address() -> usize {
    runtime_native_wrapper_address("aos_apply")
}

fn attr_access_native_wrapper_address(symbol_name: &str) -> usize {
    runtime_native_wrapper_address(symbol_name)
}

fn force_native_wrapper_address() -> usize {
    runtime_native_wrapper_address("aos_force")
}

fn force_deep_native_wrapper_address() -> usize {
    runtime_native_wrapper_address("aos_force_deep")
}

fn blackhole_native_wrapper_address() -> usize {
    runtime_native_wrapper_address("aos_blackhole_check")
}

fn write_barrier_native_wrapper_address() -> usize {
    runtime_native_wrapper_address("aos_gc_write_barrier")
}

fn env_rust_callable_address() -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == "aos_env_get")
        .expect("oracle env Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::EnvironmentAccess(binding) => {
            binding.address().as_ptr() as usize
        }
        _ => panic!("aos_env_get is an environment-access helper"),
    }
}

fn apply_rust_callable_address() -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == "aos_apply")
        .expect("oracle apply Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::CallControl(binding) => {
            binding.address().as_ptr() as usize
        }
        _ => panic!("aos_apply is a call-control helper"),
    }
}

fn attr_access_rust_callable_address(symbol_name: &str) -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == symbol_name)
        .expect("oracle attrset-access Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::AttrsetAccess(binding) => {
            binding.address().as_ptr() as usize
        }
        _ => panic!("{symbol_name} is an attrset-access helper"),
    }
}

fn blackhole_rust_callable_address() -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == "aos_blackhole_check")
        .expect("oracle blackhole-check Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::Forcing(binding) => binding.address().as_ptr() as usize,
        _ => panic!("aos_blackhole_check is a forcing helper"),
    }
}

fn write_barrier_rust_callable_address() -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == "aos_gc_write_barrier")
        .expect("oracle write-barrier Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::WriteBarrier(binding) => {
            binding.address().as_ptr() as usize
        }
        _ => panic!("aos_gc_write_barrier is a write-barrier helper"),
    }
}

fn force_rust_callable_address() -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == "aos_force")
        .expect("oracle force Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::Forcing(binding) => binding.address().as_ptr() as usize,
        _ => panic!("aos_force is a forcing helper"),
    }
}

fn force_deep_rust_callable_address() -> usize {
    let binding = runtime_symbol_rust_callable_preflight()
        .expect("oracle Rust-callable preflight builds")
        .helper_callables()
        .iter()
        .copied()
        .find(|binding| binding.symbol_name() == "aos_force_deep")
        .expect("oracle force-deep Rust callable exists");

    match binding {
        RuntimeHelperRustCallableBinding::Forcing(binding) => binding.address().as_ptr() as usize,
        _ => panic!("aos_force_deep is a forcing helper"),
    }
}

mod part_1;
mod part_2;

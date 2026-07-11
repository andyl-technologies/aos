//! Runtime ABI signatures for compiled-frame stack-map binding helpers.

use super::*;

const ENTER_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("binding", RuntimeAbiParameterKind::RawPointer),
    RuntimeAbiParameter::new("safepoint", RuntimeAbiParameterKind::U32),
    RuntimeAbiParameter::new("values", RuntimeAbiParameterKind::U32),
];

const EXIT_PARAMETERS: &[RuntimeAbiParameter] = &[
    RuntimeAbiParameter::new("rt", RuntimeAbiParameterKind::RuntimeContext),
    RuntimeAbiParameter::new("binding", RuntimeAbiParameterKind::RawPointer),
];

pub(super) const RUNTIME_JIT_STACK_MAP_ENTER_CALL_SIGNATURE: RuntimeCallSignature =
    RuntimeCallSignature::new(
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new(
                "aos_jit_stack_map_enter",
                RuntimeHelperRole::SafepointControl,
            ),
        },
        RuntimeAbiCallingConvention::ExternC,
        ENTER_PARAMETERS,
        RuntimeAbiReturnKind::Unit,
    );

pub(super) const RUNTIME_JIT_STACK_MAP_EXIT_CALL_SIGNATURE: RuntimeCallSignature =
    RuntimeCallSignature::new(
        RuntimeCallableKind::Helper {
            symbol: RuntimeHelperSymbol::new(
                "aos_jit_stack_map_exit",
                RuntimeHelperRole::SafepointControl,
            ),
        },
        RuntimeAbiCallingConvention::ExternC,
        EXIT_PARAMETERS,
        RuntimeAbiReturnKind::Unit,
    );

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn helper_call_signatures_cover_core_owned_helpers() {
        let helper_signatures = runtime_helper_call_signatures();
        let helper_symbols = helper_signatures
            .iter()
            .map(|signature| match signature.callable() {
                RuntimeCallableKind::Helper { symbol } => symbol.name(),
                other => panic!("helper signature had non-helper callable kind: {other:?}"),
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            helper_symbols,
            BTreeSet::from([
                "aos_alloc_attrs", "aos_alloc_cons", "aos_alloc_lambda", "aos_alloc_list",
                "aos_alloc_raw", "aos_alloc_string", "aos_alloc_thunk", "aos_apply",
                "aos_blackhole_check", "aos_deopt", "aos_env_get", "aos_force",
                "aos_force_deep", "aos_gc_write_barrier", "aos_has_attr",
                "aos_jit_stack_map_enter", "aos_jit_stack_map_exit", "aos_primop_call",
                "aos_select_ic", "aos_string_length", "aos_throw", "aos_update",
                "aos_upval_get",
            ])
        );
        for symbol_name in ["aos_try_begin", "aos_try_end"] {
            assert_eq!(runtime_helper_call_signature(symbol_name), None);
        }
        let expected_order = runtime_helper_symbols()
            .iter()
            .filter_map(|symbol| runtime_helper_call_signature(symbol.name()).map(|_| symbol.name()))
            .collect::<Vec<_>>();
        let actual_order = helper_signatures
            .iter()
            .map(|signature| match signature.callable() {
                RuntimeCallableKind::Helper { symbol } => symbol.name(),
                other => panic!("helper signature had non-helper callable kind: {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(actual_order, expected_order);
    }
}

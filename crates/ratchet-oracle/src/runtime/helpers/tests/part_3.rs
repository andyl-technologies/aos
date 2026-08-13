//! Runtime-helper binding inventory tests (part_3), split from `super`.

use super::super::*;
use super::*;

#[test]
fn runtime_symbol_native_export_preflight_reports_exported_wrapper_gaps() {
    let export_preflight =
        runtime_symbol_native_export_preflight().expect("native export preflight builds");
    let target_preflight = runtime_symbol_native_target_candidate_preflight()
        .expect("native target candidate preflight builds");
    let exported_wrapper_gaps = export_preflight
        .missing_bindings()
        .iter()
        .filter(|missing| missing.missing_exported_c_abi_wrapper_role().is_some())
        .collect::<Vec<_>>();

    assert!(export_preflight.export_bindings().is_empty());
    assert!(!export_preflight.is_complete());
    assert_eq!(
        export_preflight.missing_bindings().len(),
        target_preflight.candidate_bindings().len() + target_preflight.missing_bindings().len()
    );
    assert_eq!(
        exported_wrapper_gaps.len(),
        target_preflight.candidate_bindings().len()
    );
    assert!(exported_wrapper_gaps.iter().any(|missing| {
        missing.symbol_name() == "aos_alloc_attrs"
            && missing.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::Allocation)
            && missing.missing_exported_c_abi_failure_convention()
                == Some(RuntimeHelperFailureConvention::TrapToEvaluator)
    }));
    assert!(exported_wrapper_gaps.iter().any(|missing| {
        missing.symbol_name() == "aos_gc_write_barrier"
            && missing.missing_exported_c_abi_wrapper_role()
                == Some(RuntimeHelperRole::WriteBarrier)
            && missing.missing_exported_c_abi_failure_convention()
                == Some(RuntimeHelperFailureConvention::TrapToEvaluator)
    }));
    assert!(exported_wrapper_gaps.iter().any(|missing| {
        missing.symbol_name() == "aos_env_get"
            && missing.missing_exported_c_abi_wrapper_role()
                == Some(RuntimeHelperRole::EnvironmentAccess)
            && missing.missing_exported_c_abi_failure_convention()
                == Some(RuntimeHelperFailureConvention::TrapToEvaluator)
    }));
    assert!(exported_wrapper_gaps.iter().any(|missing| {
        missing.symbol_name() == "aos_apply"
            && missing.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::CallControl)
            && missing.missing_exported_c_abi_failure_convention()
                == Some(RuntimeHelperFailureConvention::TrapToEvaluator)
    }));
    for symbol_name in ["aos_has_attr", "aos_select_ic", "aos_update"] {
        assert!(exported_wrapper_gaps.iter().any(|missing| {
            missing.symbol_name() == symbol_name
                && missing.missing_exported_c_abi_wrapper_role()
                    == Some(RuntimeHelperRole::AttrsetAccess)
                && missing.missing_exported_c_abi_failure_convention()
                    == Some(RuntimeHelperFailureConvention::TrapToEvaluator)
        }));
    }
    assert!(exported_wrapper_gaps.iter().any(|missing| {
        missing.symbol_name() == "aos_force"
            && missing.missing_exported_c_abi_wrapper_role()
                == Some(RuntimeHelperRole::ForcingControl)
            && missing.missing_exported_c_abi_failure_convention()
                == Some(RuntimeHelperFailureConvention::TrapToEvaluator)
    }));
    assert!(exported_wrapper_gaps.iter().any(|missing| {
        missing.symbol_name() == "aos_force_deep"
            && missing.missing_exported_c_abi_wrapper_role()
                == Some(RuntimeHelperRole::ForcingControl)
            && missing.missing_exported_c_abi_failure_convention()
                == Some(RuntimeHelperFailureConvention::TrapToEvaluator)
    }));
    assert!(exported_wrapper_gaps.iter().any(|missing| {
        missing.symbol_name() == "aos_blackhole_check"
            && missing.missing_exported_c_abi_wrapper_role()
                == Some(RuntimeHelperRole::ForcingControl)
            && missing.missing_exported_c_abi_failure_convention()
                == Some(RuntimeHelperFailureConvention::TrapToEvaluator)
    }));
    let allocation_preflight = runtime_allocation_native_export_preflight();
    let attrs_allocation_blockers = allocation_preflight
        .readiness_for_symbol("aos_alloc_attrs")
        .expect("attrs allocation export readiness exists")
        .blockers();
    let thunk_allocation_blockers = allocation_preflight
        .readiness_for_symbol("aos_alloc_thunk")
        .expect("thunk allocation export readiness exists")
        .blockers();
    let env_preflight = runtime_env_access_native_export_preflight();
    let env_blockers = env_preflight
        .readiness_for_symbol("aos_env_get")
        .expect("env-get export readiness exists")
        .blockers();
    let apply_preflight = runtime_apply_native_export_preflight();
    let apply_blockers = apply_preflight
        .readiness_for_symbol("aos_apply")
        .expect("apply export readiness exists")
        .blockers();
    let attr_access_preflight = runtime_attr_access_native_export_preflight();
    let has_attr_blockers = attr_access_preflight
        .readiness_for_symbol("aos_has_attr")
        .expect("has-attr export readiness exists")
        .blockers();
    let select_ic_blockers = attr_access_preflight
        .readiness_for_symbol("aos_select_ic")
        .expect("select-ic export readiness exists")
        .blockers();
    let update_blockers = attr_access_preflight
        .readiness_for_symbol("aos_update")
        .expect("update export readiness exists")
        .blockers();
    let forcing_preflight = runtime_forcing_native_export_preflight();
    let blackhole_check_blockers = forcing_preflight
        .readiness_for_symbol("aos_blackhole_check")
        .expect("blackhole-check export readiness exists")
        .blockers();
    let forcing_blockers = forcing_preflight
        .readiness_for_symbol("aos_force")
        .expect("force export readiness exists")
        .blockers();
    let deep_forcing_blockers = forcing_preflight
        .readiness_for_symbol("aos_force_deep")
        .expect("deep-force export readiness exists")
        .blockers();
    let write_barrier_preflight = runtime_write_barrier_native_export_preflight();
    let write_barrier_blockers = write_barrier_preflight
        .readiness_for_symbol("aos_gc_write_barrier")
        .expect("write-barrier export readiness exists")
        .blockers();
    let attrs_export_gap = exported_wrapper_gaps
        .iter()
        .find(|missing| missing.symbol_name() == "aos_alloc_attrs")
        .expect("attrs export gap exists");
    let thunk_export_gap = exported_wrapper_gaps
        .iter()
        .find(|missing| missing.symbol_name() == "aos_alloc_thunk")
        .expect("thunk export gap exists");
    let env_export_gap = exported_wrapper_gaps
        .iter()
        .find(|missing| missing.symbol_name() == "aos_env_get")
        .expect("env-get export gap exists");
    let apply_export_gap = exported_wrapper_gaps
        .iter()
        .find(|missing| missing.symbol_name() == "aos_apply")
        .expect("apply export gap exists");
    let has_attr_export_gap = exported_wrapper_gaps
        .iter()
        .find(|missing| missing.symbol_name() == "aos_has_attr")
        .expect("has-attr export gap exists");
    let select_ic_export_gap = exported_wrapper_gaps
        .iter()
        .find(|missing| missing.symbol_name() == "aos_select_ic")
        .expect("select-ic export gap exists");
    let update_export_gap = exported_wrapper_gaps
        .iter()
        .find(|missing| missing.symbol_name() == "aos_update")
        .expect("update export gap exists");
    let blackhole_check_export_gap = exported_wrapper_gaps
        .iter()
        .find(|missing| missing.symbol_name() == "aos_blackhole_check")
        .expect("blackhole-check export gap exists");
    let force_export_gap = exported_wrapper_gaps
        .iter()
        .find(|missing| missing.symbol_name() == "aos_force")
        .expect("force export gap exists");
    let deep_force_export_gap = exported_wrapper_gaps
        .iter()
        .find(|missing| missing.symbol_name() == "aos_force_deep")
        .expect("deep-force export gap exists");
    let write_barrier_export_gap = exported_wrapper_gaps
        .iter()
        .find(|missing| missing.symbol_name() == "aos_gc_write_barrier")
        .expect("write-barrier export gap exists");

    assert_eq!(
        attrs_export_gap.missing_exported_allocation_blockers(),
        Some(attrs_allocation_blockers)
    );
    assert_eq!(
        attrs_export_gap
            .missing_exported_allocation_blockers()
            .expect("attrs allocation blockers exist"),
        [
            RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
            RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
            RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
        ]
        .as_slice()
    );
    assert!(
        !attrs_export_gap
            .missing_exported_allocation_blockers()
            .expect("attrs allocation blockers exist")
            .contains(
                &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
            )
    );
    assert_eq!(
        thunk_export_gap.missing_exported_allocation_blockers(),
        Some(thunk_allocation_blockers)
    );
    assert_eq!(
        thunk_export_gap
            .missing_exported_allocation_blockers()
            .expect("thunk allocation blockers exist"),
        [
            RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
            RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
            RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
            RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented,
        ]
        .as_slice()
    );
    assert!(
        thunk_export_gap
            .missing_exported_allocation_blockers()
            .expect("thunk allocation blockers exist")
            .contains(
                &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
            )
    );
    assert_eq!(
        env_export_gap.missing_exported_env_access_blockers(),
        Some(env_blockers)
    );
    assert_eq!(
        env_export_gap
            .missing_exported_env_access_blockers()
            .expect("env blockers exist"),
        [
            RuntimeEnvAccessNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeEnvAccessNativeExportBlocker::TrapTransferUnimplemented,
        ]
        .as_slice()
    );
    assert!(
        env_export_gap
            .missing_exported_env_access_blockers()
            .expect("env blockers exist")
            .contains(&RuntimeEnvAccessNativeExportBlocker::MissingFinalExportedWrapper)
    );
    assert!(
        env_export_gap
            .missing_exported_env_access_blockers()
            .expect("env blockers exist")
            .contains(&RuntimeEnvAccessNativeExportBlocker::TrapTransferUnimplemented)
    );
    assert!(
        !env_export_gap
            .missing_exported_env_access_blockers()
            .expect("env blockers exist")
            .contains(&RuntimeEnvAccessNativeExportBlocker::NativeEnvPointerDecodeUnimplemented)
    );
    assert!(
        !env_export_gap
            .missing_exported_env_access_blockers()
            .expect("env blockers exist")
            .contains(&RuntimeEnvAccessNativeExportBlocker::NativeEnvFrameLayoutUnimplemented)
    );
    assert!(
        !env_export_gap
            .missing_exported_env_access_blockers()
            .expect("env blockers exist")
            .contains(&RuntimeEnvAccessNativeExportBlocker::NativeEnvBorrowDisciplineUnimplemented)
    );
    assert!(
        !env_export_gap
            .missing_exported_env_access_blockers()
            .expect("env blockers exist")
            .contains(&RuntimeEnvAccessNativeExportBlocker::NativeSlotIndexDecodeUnimplemented)
    );
    assert!(
        !env_export_gap
            .missing_exported_env_access_blockers()
            .expect("env blockers exist")
            .contains(&RuntimeEnvAccessNativeExportBlocker::NativeValueReturnUnmaterialized)
    );
    assert_eq!(env_export_gap.missing_exported_allocation_blockers(), None);
    assert_eq!(
        env_export_gap.missing_exported_call_control_blockers(),
        None
    );
    assert_eq!(
        env_export_gap.missing_exported_attrset_access_blockers(),
        None
    );
    assert_eq!(env_export_gap.missing_exported_forcing_blockers(), None);
    assert_eq!(
        env_export_gap.missing_exported_write_barrier_blockers(),
        None
    );
    assert_eq!(
        apply_export_gap.missing_exported_call_control_blockers(),
        Some(apply_blockers)
    );
    assert_eq!(
        apply_export_gap
            .missing_exported_call_control_blockers()
            .expect("apply blockers exist"),
        [
            RuntimeApplyNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeApplyNativeExportBlocker::RuntimeContextDecodeUnimplemented,
            RuntimeApplyNativeExportBlocker::ActiveCallRootBindingUnimplemented,
            RuntimeApplyNativeExportBlocker::CallDepthAccountingUnimplemented,
            RuntimeApplyNativeExportBlocker::CallableDispatchBindingUnimplemented,
            RuntimeApplyNativeExportBlocker::TrapTransferUnimplemented,
            RuntimeApplyNativeExportBlocker::NativeValueReturnUnmaterialized,
        ]
        .as_slice()
    );
    assert!(
        apply_export_gap
            .missing_exported_call_control_blockers()
            .expect("apply blockers exist")
            .contains(&RuntimeApplyNativeExportBlocker::RuntimeContextDecodeUnimplemented)
    );
    assert!(
        apply_export_gap
            .missing_exported_call_control_blockers()
            .expect("apply blockers exist")
            .contains(&RuntimeApplyNativeExportBlocker::ActiveCallRootBindingUnimplemented)
    );
    assert!(
        apply_export_gap
            .missing_exported_call_control_blockers()
            .expect("apply blockers exist")
            .contains(&RuntimeApplyNativeExportBlocker::CallableDispatchBindingUnimplemented)
    );
    assert_eq!(
        apply_export_gap.missing_exported_allocation_blockers(),
        None
    );
    assert_eq!(
        apply_export_gap.missing_exported_env_access_blockers(),
        None
    );
    assert_eq!(
        apply_export_gap.missing_exported_attrset_access_blockers(),
        None
    );
    assert_eq!(apply_export_gap.missing_exported_forcing_blockers(), None);
    assert_eq!(
        apply_export_gap.missing_exported_write_barrier_blockers(),
        None
    );
    for (attr_export_gap, attr_blockers, label) in [
        (has_attr_export_gap, has_attr_blockers, "has-attr"),
        (select_ic_export_gap, select_ic_blockers, "select-ic"),
    ] {
        assert_eq!(
            attr_export_gap.missing_exported_attrset_access_blockers(),
            Some(attr_blockers)
        );
        assert_eq!(
            attr_export_gap
                .missing_exported_attrset_access_blockers()
                .expect(label),
            [
                RuntimeAttrAccessNativeExportBlocker::MissingFinalExportedWrapper,
                RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::SymbolTableBindingUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::InlineCacheSiteBindingUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::InlineCacheDispatchUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented,
                RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized,
            ]
            .as_slice()
        );
        assert!(
            attr_export_gap
                .missing_exported_attrset_access_blockers()
                .expect(label)
                .contains(&RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented)
        );
        assert!(
            attr_export_gap
                .missing_exported_attrset_access_blockers()
                .expect(label)
                .contains(&RuntimeAttrAccessNativeExportBlocker::SymbolTableBindingUnimplemented)
        );
        assert!(
            attr_export_gap
                .missing_exported_attrset_access_blockers()
                .expect(label)
                .contains(&RuntimeAttrAccessNativeExportBlocker::InlineCacheDispatchUnimplemented)
        );
        assert_eq!(attr_export_gap.missing_exported_allocation_blockers(), None);
        assert_eq!(
            attr_export_gap.missing_exported_call_control_blockers(),
            None
        );
        assert_eq!(attr_export_gap.missing_exported_env_access_blockers(), None);
        assert_eq!(attr_export_gap.missing_exported_forcing_blockers(), None);
        assert_eq!(
            attr_export_gap.missing_exported_write_barrier_blockers(),
            None
        );
    }
    assert_eq!(
        update_export_gap.missing_exported_attrset_access_blockers(),
        Some(update_blockers)
    );
    assert_eq!(
        update_export_gap
            .missing_exported_attrset_access_blockers()
            .expect("update blockers exist"),
        [
            RuntimeAttrAccessNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented,
            RuntimeAttrAccessNativeExportBlocker::ActiveAttrsetRootBindingUnimplemented,
            RuntimeAttrAccessNativeExportBlocker::NativeAttrUpdateMergeUnimplemented,
            RuntimeAttrAccessNativeExportBlocker::TrapTransferUnimplemented,
            RuntimeAttrAccessNativeExportBlocker::NativeValueReturnUnmaterialized,
        ]
        .as_slice()
    );
    assert!(
        update_export_gap
            .missing_exported_attrset_access_blockers()
            .expect("update blockers exist")
            .contains(&RuntimeAttrAccessNativeExportBlocker::RuntimeContextDecodeUnimplemented)
    );
    assert!(
        update_export_gap
            .missing_exported_attrset_access_blockers()
            .expect("update blockers exist")
            .contains(&RuntimeAttrAccessNativeExportBlocker::NativeAttrUpdateMergeUnimplemented)
    );
    assert!(
        !update_export_gap
            .missing_exported_attrset_access_blockers()
            .expect("update blockers exist")
            .contains(&RuntimeAttrAccessNativeExportBlocker::InlineCacheDispatchUnimplemented)
    );
    assert_eq!(
        update_export_gap.missing_exported_allocation_blockers(),
        None
    );
    assert_eq!(
        update_export_gap.missing_exported_call_control_blockers(),
        None
    );
    assert_eq!(
        update_export_gap.missing_exported_env_access_blockers(),
        None
    );
    assert_eq!(update_export_gap.missing_exported_forcing_blockers(), None);
    assert_eq!(
        update_export_gap.missing_exported_write_barrier_blockers(),
        None
    );
    assert_eq!(
        force_export_gap.missing_exported_forcing_blockers(),
        Some(forcing_blockers)
    );
    assert_eq!(
        force_export_gap
            .missing_exported_forcing_blockers()
            .expect("forcing blockers exist"),
        [
            RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
            RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented,
            RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
            RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented,
            RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
        ]
        .as_slice()
    );
    assert_eq!(
        deep_force_export_gap.missing_exported_forcing_blockers(),
        Some(deep_forcing_blockers)
    );
    assert_eq!(
        deep_force_export_gap
            .missing_exported_forcing_blockers()
            .expect("deep-forcing blockers exist"),
        [
            RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
            RuntimeForcingNativeExportBlocker::ActiveForceRootBindingUnimplemented,
            RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
            RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented,
            RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
        ]
        .as_slice()
    );
    assert_eq!(
        blackhole_check_export_gap.missing_exported_forcing_blockers(),
        Some(blackhole_check_blockers)
    );
    assert_eq!(
        blackhole_check_export_gap
            .missing_exported_forcing_blockers()
            .expect("blackhole-check blockers exist"),
        [
            RuntimeForcingNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented,
            RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented,
            RuntimeForcingNativeExportBlocker::TrapTransferUnimplemented,
        ]
        .as_slice()
    );
    assert!(
        force_export_gap
            .missing_exported_forcing_blockers()
            .expect("forcing blockers exist")
            .contains(&RuntimeForcingNativeExportBlocker::RuntimeContextDecodeUnimplemented)
    );
    assert!(
        force_export_gap
            .missing_exported_forcing_blockers()
            .expect("forcing blockers exist")
            .contains(&RuntimeForcingNativeExportBlocker::BlackholeProtocolBindingUnimplemented)
    );
    assert!(
        force_export_gap
            .missing_exported_forcing_blockers()
            .expect("forcing blockers exist")
            .contains(&RuntimeForcingNativeExportBlocker::ForceCacheIntegrationUnimplemented)
    );
    assert!(
        !force_export_gap
            .missing_exported_forcing_blockers()
            .expect("forcing blockers exist")
            .contains(&RuntimeForcingNativeExportBlocker::NativeValueReturnUnmaterialized)
    );
    assert_eq!(
        force_export_gap.missing_exported_allocation_blockers(),
        None
    );
    assert_eq!(
        force_export_gap.missing_exported_call_control_blockers(),
        None
    );
    assert_eq!(
        force_export_gap.missing_exported_attrset_access_blockers(),
        None
    );
    assert_eq!(
        force_export_gap.missing_exported_env_access_blockers(),
        None
    );
    assert_eq!(
        force_export_gap.missing_exported_write_barrier_blockers(),
        None
    );
    assert_eq!(
        deep_force_export_gap.missing_exported_allocation_blockers(),
        None
    );
    assert_eq!(
        deep_force_export_gap.missing_exported_call_control_blockers(),
        None
    );
    assert_eq!(
        deep_force_export_gap.missing_exported_attrset_access_blockers(),
        None
    );
    assert_eq!(
        deep_force_export_gap.missing_exported_env_access_blockers(),
        None
    );
    assert_eq!(
        deep_force_export_gap.missing_exported_write_barrier_blockers(),
        None
    );
    assert_eq!(
        write_barrier_export_gap.missing_exported_write_barrier_blockers(),
        Some(write_barrier_blockers)
    );
    assert_eq!(
        write_barrier_export_gap
            .missing_exported_write_barrier_blockers()
            .expect("write-barrier blockers exist"),
        [
            RuntimeWriteBarrierNativeExportBlocker::MissingFinalExportedWrapper,
            RuntimeWriteBarrierNativeExportBlocker::RuntimeContextAbiUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::RuntimeGcStateExtractionUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::NativeThunkPointerDecodeUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::NativeValueDecodeUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::TrapTransferUnimplemented,
            RuntimeWriteBarrierNativeExportBlocker::BarrierDispatchUnimplemented,
        ]
        .as_slice()
    );
    assert!(
        write_barrier_export_gap
            .missing_exported_write_barrier_blockers()
            .expect("write-barrier blockers exist")
            .contains(
                &RuntimeWriteBarrierNativeExportBlocker::RuntimeGcStateExtractionUnimplemented
            )
    );
    assert!(
        write_barrier_export_gap
            .missing_exported_write_barrier_blockers()
            .expect("write-barrier blockers exist")
            .contains(&RuntimeWriteBarrierNativeExportBlocker::BarrierDispatchUnimplemented)
    );
    assert_eq!(
        write_barrier_export_gap.missing_exported_allocation_blockers(),
        None
    );
    assert_eq!(
        write_barrier_export_gap.missing_exported_call_control_blockers(),
        None
    );
    assert_eq!(
        write_barrier_export_gap.missing_exported_attrset_access_blockers(),
        None
    );
    for gap in exported_wrapper_gaps.iter().filter(|missing| {
        missing.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::CallControl)
    }) {
        assert!(
            gap.missing_exported_call_control_blockers()
                .is_some_and(|blockers| !blockers.is_empty()),
            "{} call-control export gaps must retain family blockers",
            gap.symbol_name()
        );
    }
    for gap in exported_wrapper_gaps.iter().filter(|missing| {
        missing.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::AttrsetAccess)
    }) {
        assert!(
            gap.missing_exported_attrset_access_blockers()
                .is_some_and(|blockers| !blockers.is_empty()),
            "{} attrset-access export gaps must retain family blockers",
            gap.symbol_name()
        );
    }
    for gap in exported_wrapper_gaps.iter().filter(|missing| {
        missing.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::EnvironmentAccess)
    }) {
        assert!(
            gap.missing_exported_env_access_blockers()
                .is_some_and(|blockers| !blockers.is_empty()),
            "{} env-access export gaps must retain family blockers",
            gap.symbol_name()
        );
    }
    for gap in exported_wrapper_gaps.iter().filter(|missing| {
        missing.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::ForcingControl)
    }) {
        assert!(
            gap.missing_exported_forcing_blockers()
                .is_some_and(|blockers| !blockers.is_empty()),
            "{} forcing export gaps must retain family blockers",
            gap.symbol_name()
        );
    }
    for gap in exported_wrapper_gaps.iter().filter(|missing| {
        missing.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::WriteBarrier)
    }) {
        assert!(
            gap.missing_exported_write_barrier_blockers()
                .is_some_and(|blockers| !blockers.is_empty()),
            "{} write-barrier export gaps must retain family blockers",
            gap.symbol_name()
        );
    }
    assert!(export_preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "aos_apply"
            && missing.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::CallControl)
    }));
    for symbol_name in ["aos_has_attr", "aos_select_ic", "aos_update"] {
        assert!(export_preflight.missing_bindings().iter().any(|missing| {
            missing.symbol_name() == symbol_name
                && missing.missing_exported_c_abi_wrapper_role()
                    == Some(RuntimeHelperRole::AttrsetAccess)
        }));
    }
    assert!(export_preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "aos_force"
            && missing.missing_exported_c_abi_wrapper_role()
                == Some(RuntimeHelperRole::ForcingControl)
    }));
    assert!(export_preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "aos_force_deep"
            && missing.missing_exported_c_abi_wrapper_role()
                == Some(RuntimeHelperRole::ForcingControl)
    }));
    assert!(export_preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "aos_blackhole_check"
            && missing.missing_exported_c_abi_wrapper_role()
                == Some(RuntimeHelperRole::ForcingControl)
    }));
    assert!(export_preflight.missing_bindings().iter().any(|missing| {
        missing
            .missing_native_target_candidate()
            .is_some_and(|gap| {
                gap.missing_builtin_wrapper()
                    .is_some_and(|binding| binding.symbol_name() == "nix.builtin.derivationStrict")
            })
    }));
    assert!(export_preflight.missing_bindings().iter().any(|missing| {
            missing
                .missing_native_target_candidate()
                .is_some_and(|gap| {
                    gap.missing_builtin_wrapper().is_some_and(|binding| {
                        binding.symbol_name() == "nix.builtin.derivationStrict"
                    }) && gap.missing_builtin_wrapper_blockers().is_some_and(|blockers| {
                        blockers.contains(
                            &RuntimeBuiltinNativeWrapperBlocker::BuiltinDispatchBindingUnimplemented,
                        ) && blockers.contains(
                            &RuntimeBuiltinNativeWrapperBlocker::EvaluatorCallFrameBindingUnimplemented,
                        ) && blockers.contains(
                            &RuntimeBuiltinNativeWrapperBlocker::ActiveArgumentRootRegistrationUnimplemented,
                        ) && blockers.contains(
                            &RuntimeBuiltinNativeWrapperBlocker::TrapTransferUnimplemented,
                        )
                    })
                })
        }));
}

#[test]
fn runtime_symbol_native_export_preflight_preserves_runtime_symbol_order() {
    let export_preflight =
        runtime_symbol_native_export_preflight().expect("native export preflight builds");
    let manifest_symbols = runtime_symbol_binding_manifest()
        .expect("binding manifest builds")
        .into_iter()
        .map(|entry| entry.symbol_name().to_owned())
        .collect::<Vec<_>>();
    let export_symbols = export_preflight
        .missing_bindings()
        .iter()
        .map(RuntimeSymbolNativeExportMissingBinding::symbol_name)
        .collect::<Vec<_>>();

    assert_eq!(export_symbols, manifest_symbols);
}

#[test]
fn runtime_symbol_native_export_preflight_converts_synthetic_report_to_plan() {
    let export_binding = RuntimeSymbolNativeExportBinding::new(
        "aos_alloc_attrs".to_owned(),
        RuntimeHelperRole::Allocation,
        RuntimeHelperFailureConvention::TrapToEvaluator,
    );
    let preflight =
        RuntimeSymbolNativeExportPreflight::new(vec![export_binding.clone()], Vec::new());

    let plan = preflight
        .into_native_export_plan()
        .expect("synthetic native-export metadata preflight converts");

    assert_eq!(plan.export_bindings(), &[export_binding]);
    assert_eq!(plan.export_bindings()[0].symbol_name(), "aos_alloc_attrs");
    assert_eq!(
        plan.export_bindings()[0].helper_role(),
        RuntimeHelperRole::Allocation
    );
    assert_eq!(
        plan.export_bindings()[0].failure_convention(),
        RuntimeHelperFailureConvention::TrapToEvaluator
    );
}

#[test]
fn runtime_symbol_native_export_plan_rejects_until_all_symbols_are_exported() {
    let error = runtime_symbol_native_export_plan()
        .expect_err("current native-export plan rejects incomplete metadata");
    let RuntimeSymbolNativeExportPlanError::Incomplete {
        missing_count,
        preflight,
    } = error
    else {
        panic!("expected incomplete native-export plan error");
    };

    assert_eq!(missing_count, preflight.missing_bindings().len());
    assert!(!preflight.is_complete());
    assert!(preflight.export_bindings().is_empty());
    assert!(preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "aos_alloc_attrs"
            && missing.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::Allocation)
    }));
    assert!(preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "aos_apply"
            && missing.missing_exported_c_abi_wrapper_role() == Some(RuntimeHelperRole::CallControl)
    }));
    assert!(preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "aos_force"
            && missing.missing_exported_c_abi_wrapper_role()
                == Some(RuntimeHelperRole::ForcingControl)
    }));
    assert!(preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "aos_force_deep"
            && missing.missing_exported_c_abi_wrapper_role()
                == Some(RuntimeHelperRole::ForcingControl)
    }));
}

#[test]
fn runtime_symbol_rust_callable_preflight_reports_current_gaps() {
    let callable_preflight =
        runtime_symbol_rust_callable_preflight().expect("callable preflight builds");
    let registration_preflight =
        runtime_symbol_registration_preflight().expect("registration preflight builds");
    let callable_helper_symbols = callable_preflight
        .helper_callables()
        .iter()
        .copied()
        .map(RuntimeHelperRustCallableBinding::symbol_name)
        .collect::<Vec<_>>();

    assert!(!callable_preflight.is_complete());
    assert_eq!(
        callable_preflight.helper_callables(),
        runtime_helper_rust_callable_bindings().as_slice()
    );
    assert_eq!(
        callable_helper_symbols,
        registration_preflight
            .helper_bindings()
            .iter()
            .copied()
            .map(RuntimeHelperBinding::symbol_name)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        callable_preflight.missing_bindings(),
        registration_preflight.missing_bindings()
    );
    assert!(
        callable_preflight
            .helper_callables()
            .iter()
            .any(|callable| callable.symbol_name() == "aos_force"
                && callable.role() == RuntimeHelperRole::ForcingControl)
    );
    assert!(
        callable_preflight
            .helper_callables()
            .iter()
            .any(|callable| callable.symbol_name() == "aos_apply"
                && callable.role() == RuntimeHelperRole::CallControl)
    );
    assert!(
        callable_preflight
            .helper_callables()
            .iter()
            .any(|callable| callable.symbol_name() == "aos_force_deep"
                && callable.role() == RuntimeHelperRole::ForcingControl)
    );
    assert!(
        callable_preflight
            .helper_callables()
            .iter()
            .any(|callable| {
                callable.symbol_name() == "aos_blackhole_check"
                    && callable.role() == RuntimeHelperRole::ForcingControl
            })
    );
    assert!(callable_preflight.missing_bindings().iter().any(|missing| {
        missing.symbol_name() == "nix.builtin.derivationStrict" && missing.helper_role().is_none()
    }));
}

#[test]
fn runtime_symbol_registration_plan_rejects_until_all_symbols_are_bound() {
    let error =
        runtime_symbol_registration_plan().expect_err("complete registration is not available yet");

    let RuntimeSymbolRegistrationError::Incomplete {
        missing_count,
        preflight,
    } = error
    else {
        panic!("registration should fail because bindings are incomplete");
    };
    assert_eq!(missing_count, preflight.missing_bindings().len());
    assert!(!preflight.is_complete());
    assert_eq!(preflight.helper_bindings(), runtime_helper_bindings());
}

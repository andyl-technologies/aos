//! Runtime allocator tests (part 2), split from `super`.

use super::super::*;
use super::*;

#[test]
fn tier_a_allocation_vtable_routes_every_worker_entrypoint() {
    let mut allocator =
        RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");
    let vtable = allocator.allocation_vtable();

    let thunk = vtable
        .aos_alloc_thunk(&mut allocator)
        .expect("thunk allocates");
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        1,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocThunk,
        thunk,
        allocator.stats(),
    );

    let lambda = vtable
        .aos_alloc_lambda(&mut allocator)
        .expect("lambda allocates");
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        2,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocLambda,
        lambda,
        allocator.stats(),
    );

    let attrs = vtable
        .aos_alloc_attrs(&mut allocator, 7, 2)
        .expect("attrs allocates");
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        3,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocAttrs,
        attrs,
        allocator.stats(),
    );

    let cons = vtable
        .aos_alloc_cons(&mut allocator)
        .expect("cons allocates");
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        4,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocCons,
        cons,
        allocator.stats(),
    );

    let list = vtable
        .aos_alloc_list(&mut allocator, 3)
        .expect("list allocates");
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        5,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocList,
        list,
        allocator.stats(),
    );

    let string = vtable
        .aos_alloc_string(&mut allocator, 5)
        .expect("string allocates");
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        6,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocString,
        string,
        allocator.stats(),
    );

    let raw = vtable
        .aos_alloc_raw(&mut allocator, 8, 8, 0x7261_7770)
        .expect("raw allocates");
    assert_last_safepoint(
        allocator.allocation_safepoints(),
        7,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationEntryPoint::AosAllocRaw,
        raw,
        allocator.stats(),
    );
}

#[test]
fn allocation_rust_callable_bindings_preserve_entrypoint_inventory() {
    let bindings = runtime_allocation_rust_callable_bindings();
    let expected = [
        (
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            RuntimeAllocationRustCallableShape::AllocatorU32U32,
            native_aos_alloc_attrs as RuntimeAllocationAttrsFn as *const (),
        ),
        (
            RuntimeAllocationEntryPoint::AosAllocCons,
            RuntimeAllocationRustCallableShape::AllocatorOnly,
            native_aos_alloc_cons as RuntimeAllocationConsFn as *const (),
        ),
        (
            RuntimeAllocationEntryPoint::AosAllocLambda,
            RuntimeAllocationRustCallableShape::AllocatorOnly,
            native_aos_alloc_lambda as RuntimeAllocationLambdaFn as *const (),
        ),
        (
            RuntimeAllocationEntryPoint::AosAllocList,
            RuntimeAllocationRustCallableShape::AllocatorUsize,
            native_aos_alloc_list as RuntimeAllocationListFn as *const (),
        ),
        (
            RuntimeAllocationEntryPoint::AosAllocRaw,
            RuntimeAllocationRustCallableShape::AllocatorUsizeUsizeU32,
            native_aos_alloc_raw as RuntimeAllocationRawFn as *const (),
        ),
        (
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationRustCallableShape::AllocatorUsize,
            native_aos_alloc_string as RuntimeAllocationStringFn as *const (),
        ),
        (
            RuntimeAllocationEntryPoint::AosAllocThunk,
            RuntimeAllocationRustCallableShape::AllocatorOnly,
            native_aos_alloc_thunk as RuntimeAllocationThunkFn as *const (),
        ),
    ];

    assert_eq!(bindings.len(), expected.len());
    assert_eq!(
        bindings
            .iter()
            .copied()
            .map(RuntimeAllocationRustCallableBinding::entrypoint)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_allocation_entrypoints()
    );
    assert_eq!(
        bindings
            .iter()
            .copied()
            .map(|binding| (
                binding.entrypoint(),
                binding.shape(),
                binding.address().as_ptr(),
            ))
            .collect::<Vec<_>>()
            .as_slice(),
        expected.as_slice()
    );

    assert_eq!(
        bindings
            .iter()
            .copied()
            .map(|binding| binding.entrypoint().abi_signature())
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_allocation_abi_signatures()
    );

    for binding in bindings {
        assert_eq!(binding.symbol_name(), binding.entrypoint().symbol_name());
        assert_eq!(binding.entrypoint().rust_callable_binding(), binding);
        assert_eq!(binding.shape(), binding.entrypoint().rust_callable_shape());
        assert_eq!(
            binding.address(),
            binding.entrypoint().rust_callable_address()
        );
        assert!(
            binding.address().is_non_null(),
            "{} has a callable allocation address",
            binding.symbol_name()
        );
    }
}

#[test]
fn allocation_native_export_preflight_preserves_frozen_abi_and_storage_callables() {
    let preflight = runtime_allocation_native_export_preflight();

    assert!(!preflight.is_complete());
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeAllocationNativeExportReadiness::entrypoint)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_allocation_entrypoints()
    );
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeAllocationNativeExportReadiness::abi_signature)
            .collect::<Vec<_>>()
            .as_slice(),
        runtime_allocation_abi_signatures()
    );
    assert_eq!(
        preflight
            .readiness()
            .iter()
            .map(RuntimeAllocationNativeExportReadiness::rust_callable_binding)
            .collect::<Vec<_>>(),
        runtime_allocation_rust_callable_bindings()
    );

    for record in preflight.readiness() {
        assert_eq!(record.symbol_name(), record.entrypoint().symbol_name());
        assert_eq!(
            record.blockers(),
            record.entrypoint().native_export_blockers()
        );
        assert!(!record.is_export_ready());
        match record.entrypoint() {
            RuntimeAllocationEntryPoint::AosAllocCons
            | RuntimeAllocationEntryPoint::AosAllocLambda
            | RuntimeAllocationEntryPoint::AosAllocThunk => {
                assert_eq!(
                        record.blockers(),
                        [
                            RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
                            RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
                            RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
                            RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
                            RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented,
                        ]
                        .as_slice()
                    );
            }
            RuntimeAllocationEntryPoint::AosAllocAttrs
            | RuntimeAllocationEntryPoint::AosAllocList
            | RuntimeAllocationEntryPoint::AosAllocRaw
            | RuntimeAllocationEntryPoint::AosAllocString => {
                assert_eq!(
                    record.blockers(),
                    [
                        RuntimeAllocationNativeExportBlocker::MissingFinalExportedWrapper,
                        RuntimeAllocationNativeExportBlocker::RuntimeContextAbiUnimplemented,
                        RuntimeAllocationNativeExportBlocker::TrapTransferUnimplemented,
                        RuntimeAllocationNativeExportBlocker::TypedPointerReturnUnmaterialized,
                    ]
                    .as_slice()
                );
            }
        }
        assert_eq!(
            preflight.readiness_for_symbol(record.symbol_name()),
            Some(record)
        );
    }
}

#[test]
fn allocation_native_export_preflight_marks_semantic_payload_gaps() {
    let preflight = runtime_allocation_native_export_preflight();
    let semantic_symbols = [
        RuntimeAllocationEntryPoint::AosAllocCons,
        RuntimeAllocationEntryPoint::AosAllocLambda,
        RuntimeAllocationEntryPoint::AosAllocThunk,
    ];
    let storage_only_symbols = [
        RuntimeAllocationEntryPoint::AosAllocAttrs,
        RuntimeAllocationEntryPoint::AosAllocList,
        RuntimeAllocationEntryPoint::AosAllocRaw,
        RuntimeAllocationEntryPoint::AosAllocString,
    ];

    for entrypoint in semantic_symbols {
        let record = preflight
            .readiness_for_symbol(entrypoint.symbol_name())
            .expect("semantic allocation export readiness exists");
        assert!(
            record.blockers().contains(
                &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
            ),
            "{} must initialize frozen ABI semantic payloads",
            entrypoint.symbol_name()
        );
    }

    for entrypoint in storage_only_symbols {
        let record = preflight
            .readiness_for_symbol(entrypoint.symbol_name())
            .expect("storage allocation export readiness exists");
        assert!(
            !record.blockers().contains(
                &RuntimeAllocationNativeExportBlocker::SemanticPayloadInitializationUnimplemented
            ),
            "{} has no extra semantic payload beyond storage reservation",
            entrypoint.symbol_name()
        );
    }
}

#[test]
fn allocation_native_callables_route_through_request_wall() {
    let mut allocator =
        RuntimeAllocator::tier_a_with_initial_chunk_bytes(512).expect("allocator creates");

    let allocation =
        native_aos_alloc_attrs(&mut allocator, 7, 2).expect("native attrs wrapper allocates");
    assert_eq!(
        allocation.kind,
        HeapObjectKind::Attrs { shape: 7, slots: 2 }
    );
    assert_last_request_safepoint(
        allocator.allocation_safepoints(),
        1,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationRequest::Attrs { shape: 7, slots: 2 },
        allocation,
        allocator.stats(),
    );

    let allocation = native_aos_alloc_cons(&mut allocator).expect("native cons wrapper allocates");
    assert_eq!(allocation.kind, HeapObjectKind::Cons);
    assert_last_request_safepoint(
        allocator.allocation_safepoints(),
        2,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationRequest::Cons,
        allocation,
        allocator.stats(),
    );

    let allocation =
        native_aos_alloc_lambda(&mut allocator).expect("native lambda wrapper allocates");
    assert_eq!(allocation.kind, HeapObjectKind::Lambda);
    assert_last_request_safepoint(
        allocator.allocation_safepoints(),
        3,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationRequest::Lambda,
        allocation,
        allocator.stats(),
    );

    let allocation =
        native_aos_alloc_list(&mut allocator, 3).expect("native list wrapper allocates");
    assert_eq!(allocation.kind, HeapObjectKind::List { len: 3 });
    assert_last_request_safepoint(
        allocator.allocation_safepoints(),
        4,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationRequest::List { len: 3 },
        allocation,
        allocator.stats(),
    );

    let allocation = native_aos_alloc_raw(&mut allocator, 8, 8, 0x7261_7770)
        .expect("native raw wrapper allocates");
    assert_eq!(
        allocation.kind,
        HeapObjectKind::Raw {
            type_tag: 0x7261_7770
        }
    );
    assert_last_request_safepoint(
        allocator.allocation_safepoints(),
        5,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationRequest::Raw {
            size: 8,
            align: 8,
            type_tag: 0x7261_7770,
        },
        allocation,
        allocator.stats(),
    );

    let allocation =
        native_aos_alloc_string(&mut allocator, 5).expect("native string wrapper allocates");
    assert_eq!(allocation.kind, HeapObjectKind::String { len: 5 });
    assert_last_request_safepoint(
        allocator.allocation_safepoints(),
        6,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationRequest::String { len: 5 },
        allocation,
        allocator.stats(),
    );

    let allocation =
        native_aos_alloc_thunk(&mut allocator).expect("native thunk wrapper allocates");
    assert_eq!(allocation.kind, HeapObjectKind::Thunk);
    assert_last_request_safepoint(
        allocator.allocation_safepoints(),
        7,
        RuntimeAllocatorTier::TierAOneShot,
        RuntimeAllocationRequest::Thunk,
        allocation,
        allocator.stats(),
    );
}

#[test]
fn allocation_entrypoint_symbols_round_trip() {
    assert_eq!(
        runtime_allocation_entrypoints(),
        [
            RuntimeAllocationEntryPoint::AosAllocAttrs,
            RuntimeAllocationEntryPoint::AosAllocCons,
            RuntimeAllocationEntryPoint::AosAllocLambda,
            RuntimeAllocationEntryPoint::AosAllocList,
            RuntimeAllocationEntryPoint::AosAllocRaw,
            RuntimeAllocationEntryPoint::AosAllocString,
            RuntimeAllocationEntryPoint::AosAllocThunk,
        ]
    );

    for entrypoint in runtime_allocation_entrypoints() {
        assert_eq!(
            RuntimeAllocationEntryPoint::from_symbol_name(entrypoint.symbol_name()),
            Some(*entrypoint)
        );
        assert_eq!(
            RuntimeAllocationAbiSignature::from_symbol_name(entrypoint.symbol_name()),
            Some(entrypoint.abi_signature())
        );
    }
    for symbol in runtime_helper_symbols()
        .iter()
        .copied()
        .filter(|symbol| symbol.role() != RuntimeHelperRole::Allocation)
    {
        assert_eq!(
            RuntimeAllocationEntryPoint::from_symbol_name(symbol.name()),
            None,
            "{} is not an allocation entry point",
            symbol.name()
        );
        assert_eq!(
            RuntimeAllocationAbiSignature::from_symbol_name(symbol.name()),
            None,
            "{} has no allocation ABI signature",
            symbol.name()
        );
    }
    assert_eq!(
        RuntimeAllocationEntryPoint::from_symbol_name("nix.builtin.derivationStrict"),
        None
    );
    assert_eq!(
        RuntimeAllocationAbiSignature::from_symbol_name("nix.builtin.derivationStrict"),
        None
    );
}

#[test]
fn allocation_abi_signatures_pin_runtime_parameters() {
    fn assert_signature(
        entrypoint: RuntimeAllocationEntryPoint,
        parameters: &[RuntimeAllocationAbiParameter],
        return_kind: RuntimeAllocationAbiReturnKind,
    ) {
        let signature = entrypoint.abi_signature();
        assert_eq!(signature.entrypoint(), entrypoint);
        assert_eq!(signature.parameters(), parameters);
        assert_eq!(signature.return_kind(), return_kind);
    }

    assert_eq!(
        runtime_allocation_abi_signatures()
            .iter()
            .copied()
            .map(RuntimeAllocationAbiSignature::entrypoint)
            .collect::<Vec<_>>(),
        runtime_allocation_entrypoints()
    );

    for signature in runtime_allocation_abi_signatures().iter().copied() {
        assert_eq!(signature.entrypoint().abi_signature(), signature);
        assert_eq!(
            signature.symbol_name(),
            signature.entrypoint().symbol_name()
        );
        assert_eq!(
            signature.parameters().first().copied(),
            Some(RuntimeAllocationAbiParameter::new(
                "rt",
                RuntimeAllocationAbiParameterKind::RuntimeContext,
            )),
            "{} takes the runtime context first",
            signature.symbol_name()
        );
    }

    assert_signature(
        RuntimeAllocationEntryPoint::AosAllocThunk,
        &[
            RuntimeAllocationAbiParameter::new(
                "rt",
                RuntimeAllocationAbiParameterKind::RuntimeContext,
            ),
            RuntimeAllocationAbiParameter::new(
                "code_ptr",
                RuntimeAllocationAbiParameterKind::CodePointer,
            ),
            RuntimeAllocationAbiParameter::new(
                "env",
                RuntimeAllocationAbiParameterKind::EnvPointer,
            ),
        ],
        RuntimeAllocationAbiReturnKind::ThunkPointer,
    );
    assert_signature(
        RuntimeAllocationEntryPoint::AosAllocLambda,
        &[
            RuntimeAllocationAbiParameter::new(
                "rt",
                RuntimeAllocationAbiParameterKind::RuntimeContext,
            ),
            RuntimeAllocationAbiParameter::new(
                "code_ptr",
                RuntimeAllocationAbiParameterKind::CodePointer,
            ),
            RuntimeAllocationAbiParameter::new(
                "env",
                RuntimeAllocationAbiParameterKind::EnvPointer,
            ),
        ],
        RuntimeAllocationAbiReturnKind::LambdaPointer,
    );
    assert_signature(
        RuntimeAllocationEntryPoint::AosAllocAttrs,
        [
            RuntimeAllocationAbiParameter::new(
                "rt",
                RuntimeAllocationAbiParameterKind::RuntimeContext,
            ),
            RuntimeAllocationAbiParameter::new("shape", RuntimeAllocationAbiParameterKind::ShapeId),
            RuntimeAllocationAbiParameter::new("slots", RuntimeAllocationAbiParameterKind::U32),
        ]
        .as_slice(),
        RuntimeAllocationAbiReturnKind::AttrsPointer,
    );
    assert_signature(
        RuntimeAllocationEntryPoint::AosAllocCons,
        &[
            RuntimeAllocationAbiParameter::new(
                "rt",
                RuntimeAllocationAbiParameterKind::RuntimeContext,
            ),
            RuntimeAllocationAbiParameter::new("head", RuntimeAllocationAbiParameterKind::Value),
            RuntimeAllocationAbiParameter::new(
                "tail",
                RuntimeAllocationAbiParameterKind::ListPointer,
            ),
        ],
        RuntimeAllocationAbiReturnKind::ListPointer,
    );
    assert_signature(
        RuntimeAllocationEntryPoint::AosAllocList,
        [
            RuntimeAllocationAbiParameter::new(
                "rt",
                RuntimeAllocationAbiParameterKind::RuntimeContext,
            ),
            RuntimeAllocationAbiParameter::new("len", RuntimeAllocationAbiParameterKind::Usize),
        ]
        .as_slice(),
        RuntimeAllocationAbiReturnKind::ListPointer,
    );
    assert_signature(
        RuntimeAllocationEntryPoint::AosAllocString,
        [
            RuntimeAllocationAbiParameter::new(
                "rt",
                RuntimeAllocationAbiParameterKind::RuntimeContext,
            ),
            RuntimeAllocationAbiParameter::new("len", RuntimeAllocationAbiParameterKind::Usize),
        ]
        .as_slice(),
        RuntimeAllocationAbiReturnKind::StringHeaderPointer,
    );
    assert_signature(
        RuntimeAllocationEntryPoint::AosAllocRaw,
        &[
            RuntimeAllocationAbiParameter::new(
                "rt",
                RuntimeAllocationAbiParameterKind::RuntimeContext,
            ),
            RuntimeAllocationAbiParameter::new("size", RuntimeAllocationAbiParameterKind::Usize),
            RuntimeAllocationAbiParameter::new("align", RuntimeAllocationAbiParameterKind::Usize),
            RuntimeAllocationAbiParameter::new(
                "type_tag",
                RuntimeAllocationAbiParameterKind::TypeTag,
            ),
        ],
        RuntimeAllocationAbiReturnKind::RawPointer,
    );
}

#[test]
fn invalid_tier_a_chunk_size_is_rejected() {
    let error = RuntimeAllocator::tier_a_with_initial_chunk_bytes(0)
        .expect_err("zero-sized chunks are invalid");

    assert_eq!(error, ArenaError::InvalidChunkSize { chunk_bytes: 0 });
}

#[test]
fn gc_stress_period_rejects_zero() {
    assert_eq!(
        GcStressPolicy::every_n_safepoints(0),
        Err(GcStressPolicyError::ZeroPeriod)
    );
}

#[test]
fn gc_stress_every_safepoint_records_poll_reason() {
    let mut allocator =
        RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("allocator creates");
    allocator.set_gc_stress_policy(GcStressPolicy::every_safepoint());

    allocator.aos_alloc_thunk().expect("thunk allocates");

    let event = allocator
        .allocation_safepoints()
        .last()
        .expect("safepoint records");
    assert_eq!(event.sequence(), 1);
    assert_eq!(
        event.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    let poll = event.collector_poll().expect("poll request records");
    assert_eq!(poll.sequence(), event.sequence());
    assert_eq!(poll.tier(), RuntimeAllocatorTier::TierAOneShot);
    assert_eq!(event.request(), RuntimeAllocationRequest::Thunk);
    assert_eq!(poll.request(), RuntimeAllocationRequest::Thunk);
    assert_eq!(
        poll.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocThunk
    );
    assert_eq!(
        poll.reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );
    assert_eq!(poll.stats_after(), event.stats_after());
    assert_eq!(
        allocator
            .allocation_safepoints()
            .last_safepoint_collector_poll(),
        Some(poll)
    );
}

#[test]
fn gc_stress_periodic_policy_records_poll_on_matching_sequences() {
    let mut allocator = RuntimeAllocator::tier_a_with_initial_chunk_bytes(128)
        .expect("allocator creates")
        .with_gc_stress_policy(GcStressPolicy::every_n_safepoints(2).expect("period is non-zero"));

    allocator.aos_alloc_thunk().expect("first allocation");
    assert_eq!(
        allocator
            .allocation_safepoints()
            .last()
            .expect("first safepoint")
            .gc_poll_reason(),
        None
    );

    allocator.aos_alloc_lambda().expect("second allocation");
    assert_eq!(
        allocator
            .allocation_safepoints()
            .last()
            .expect("second safepoint")
            .gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEveryNSafepoints { period: 2 })
    );

    allocator.aos_alloc_cons().expect("third allocation");
    assert_eq!(
        allocator
            .allocation_safepoints()
            .last()
            .expect("third safepoint")
            .gc_poll_reason(),
        None
    );
}

#[test]
fn periodic_gc_stress_uses_allocator_lifetime_sequence() {
    let mut allocator =
        RuntimeAllocator::tier_a_with_initial_chunk_bytes(128).expect("allocator creates");
    allocator.aos_alloc_thunk().expect("first allocation");

    allocator
        .set_gc_stress_policy(GcStressPolicy::every_n_safepoints(2).expect("period is non-zero"));
    allocator.aos_alloc_lambda().expect("second allocation");

    let event = allocator
        .allocation_safepoints()
        .last()
        .expect("second safepoint");
    assert_eq!(event.sequence(), 2);
    assert_eq!(
        event.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEveryNSafepoints { period: 2 })
    );
}

#[test]
fn enabled_gc_stress_polls_when_safepoint_sequence_saturates() {
    let mut arena = BumpArena::with_initial_chunk_bytes(64).expect("arena creates");
    let request = RuntimeAllocationRequest::Raw {
        size: 16,
        align: 8,
        type_tag: 0x7261_7770,
    };
    let allocation = arena
        .aos_alloc_raw(16, 8, 0x7261_7770)
        .expect("raw allocation succeeds");
    let mut state = AllocationSafepointState {
        count: u64::MAX - 1,
        last: None,
    };
    let policy = GcStressPolicy::every_n_safepoints(2).expect("period is non-zero");

    state.record(
        RuntimeAllocatorTier::TierAOneShot,
        request,
        allocation,
        arena.stats(),
        policy,
    );
    let event = state.last().expect("saturated safepoint records");
    assert_eq!(event.sequence(), u64::MAX);
    assert_eq!(event.request(), request);
    assert_eq!(
        event.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressSequenceSaturated)
    );
    let poll = event.collector_poll().expect("poll records");
    assert_eq!(poll.request(), request);
    assert_eq!(
        poll.reason(),
        AllocationGcPollReason::GcStressSequenceSaturated
    );

    state.record(
        RuntimeAllocatorTier::TierAOneShot,
        request,
        allocation,
        arena.stats(),
        policy,
    );
    let event = state.last().expect("post-saturation safepoint records");
    assert_eq!(event.sequence(), u64::MAX);
    assert_eq!(event.request(), request);
    assert_eq!(
        event.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressSequenceSaturated)
    );
    let poll = state.last_safepoint_collector_poll().expect("poll records");
    assert_eq!(poll.sequence(), u64::MAX);
    assert_eq!(poll.request(), request);
}

#[test]
fn permanent_shared_allocations_can_record_gc_stress_poll_reason() {
    let mut allocator =
        PermanentSharedAllocator::with_initial_chunk_bytes(128).expect("allocator creates");
    allocator.set_gc_stress_policy(GcStressPolicy::every_safepoint());

    allocator.test_alloc_string(5).expect("string allocates");

    let event = allocator
        .allocation_safepoints()
        .last()
        .expect("safepoint records");
    assert_eq!(event.tier(), RuntimeAllocatorTier::PermanentShared);
    assert_eq!(
        event.gc_poll_reason(),
        Some(AllocationGcPollReason::GcStressEverySafepoint)
    );
    let poll = allocator
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("permanent poll records");
    assert_eq!(poll.sequence(), event.sequence());
    assert_eq!(poll.tier(), RuntimeAllocatorTier::PermanentShared);
    assert_eq!(event.request(), RuntimeAllocationRequest::String { len: 5 });
    assert_eq!(poll.request(), RuntimeAllocationRequest::String { len: 5 });
    assert_eq!(
        poll.entrypoint(),
        RuntimeAllocationEntryPoint::AosAllocString
    );
    assert_eq!(
        poll.reason(),
        AllocationGcPollReason::GcStressEverySafepoint
    );
    assert_eq!(poll.stats_after(), event.stats_after());
}

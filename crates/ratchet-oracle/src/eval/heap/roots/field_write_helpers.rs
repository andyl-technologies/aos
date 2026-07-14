//! Free helpers for heap-field write validation and application: identity
//! checks, write-object validation/construction, suspended-thunk field
//! rewriting, and closure edge pushers.
//!
//! Moved verbatim from `heap/roots.rs` under the RFC-0007 §2 file-size cap;
//! the parent re-exports every public path and glob-imports each child so
//! sibling references keep resolving.

use super::*;

pub(super) fn gc_address_for_value(value: Value) -> Result<GcHeapAddress, EvalHeapError> {
    let (_tag, ptr) = heap_ptr(value)?;
    GcHeapAddress::new(ptr.as_ptr() as usize).map_err(EvalHeapError::GenerationalGc)
}

pub(super) fn gc_address_for_record(record: &HeapRecord) -> Result<GcHeapAddress, EvalHeapError> {
    GcHeapAddress::new(record.ptr.as_ptr() as usize).map_err(EvalHeapError::GenerationalGc)
}

pub(super) const fn generation_for_record(record: &HeapRecord) -> HeapGeneration {
    record.generation
}

pub(super) const fn expected_direct_heap_field_write_generation(
    allocation_domain: HeapAllocationDomain,
) -> HeapGeneration {
    match allocation_domain {
        HeapAllocationDomain::Worker => HeapGeneration::Old,
        HeapAllocationDomain::PermanentShared => HeapGeneration::Permanent,
    }
}

pub(super) fn heap_object_value_raw_eq(left: &HeapObjectValue, right: &HeapObjectValue) -> bool {
    match (left, right) {
        (HeapObjectValue::String(left), HeapObjectValue::String(right)) => left == right,
        (HeapObjectValue::List(left), HeapObjectValue::List(right)) => left.raw_eq(right),
        (HeapObjectValue::Lambda(left), HeapObjectValue::Lambda(right)) => left.raw_eq(right),
        (HeapObjectValue::Primop(left), HeapObjectValue::Primop(right)) => left.raw_eq(right),
        (HeapObjectValue::Thunk(left), HeapObjectValue::Thunk(right)) => left.raw_eq(right),
        _ => false,
    }
}

pub(super) fn copied_heap_field_write_identity_matches(
    left: &AllocationCollectorPollCopiedHeapFieldWrite,
    right: &AllocationCollectorPollCopiedHeapFieldWrite,
) -> bool {
    left.allocation_domain() == right.allocation_domain()
        && left.validation_object() == right.validation_object()
        && left.writeback_object() == right.writeback_object()
        && left.field_index() == right.field_index()
        && left.source() == right.source()
}

pub(super) fn direct_heap_field_write_identity_matches(
    left: &AllocationCollectorPollDirectHeapFieldWrite,
    right: &AllocationCollectorPollDirectHeapFieldWrite,
) -> bool {
    left.allocation_domain() == right.allocation_domain()
        && left.writeback_object() == right.writeback_object()
        && left.field_index() == right.field_index()
        && left.source() == right.source()
}

pub(super) fn validate_copied_heap_field_write_object_source(
    object: &HeapObjectValue,
    write: &AllocationCollectorPollCopiedHeapFieldWrite,
) -> Result<(), EvalHeapError> {
    if validate_captured_environment_source(object, write.source())
        .map_err(EvalHeapError::Environment)?
    {
        return Ok(());
    }
    match (object, write.source()) {
        (HeapObjectValue::List(_), HeapEdgeSource::ListElement { .. }) => Ok(()),
        (HeapObjectValue::Primop(primop), HeapEdgeSource::PrimopArgument { index })
            if *index < primop.args().len() =>
        {
            Ok(())
        }
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) if *index < lambda.with_scope_env().scopes().len() => Ok(()),
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) if *index < lambda.scoped_global_env().scopes().len() => Ok(()),
        (HeapObjectValue::Thunk(thunk), source)
            if validate_forced_thunk_cached_result_write_source(thunk, source)? =>
        {
            Ok(())
        }
        (HeapObjectValue::Thunk(thunk), source)
            if validate_parallel_thunk_payload_write_source(thunk, source)? =>
        {
            Ok(())
        }
        (HeapObjectValue::Thunk(thunk), source)
            if validate_suspended_thunk_field_write_source(thunk, source)? =>
        {
            Ok(())
        }
        _ => Err(
            EvalHeapError::CollectorPollCopiedHeapFieldWriteUnsupportedSource {
                writeback_object: write.writeback_object(),
                field_index: write.field_index(),
                field_source: write.source().clone(),
            },
        ),
    }
}

/// Source-shape validation for a flat-list direct writeback target.
///
/// The flat analog of the `(List, ListElement)` arm of
/// [`validate_direct_heap_field_write_object_source`]: a flat list only
/// carries `ListElement` fields.
pub(super) fn validate_flat_list_direct_heap_field_write_source(
    write: &AllocationCollectorPollDirectHeapFieldWrite,
) -> Result<(), EvalHeapError> {
    if matches!(write.source(), HeapEdgeSource::ListElement { .. }) {
        return Ok(());
    }
    Err(
        EvalHeapError::CollectorPollDirectHeapFieldWriteUnsupportedSource {
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            field_source: write.source().clone(),
        },
    )
}

/// Rewrites one element of a staged flat-list spine.
///
/// The flat analog of [`record_owned_heap_field_write_object`]'s
/// `(List, ListElement)` arm: clone-and-replace over the staged spine, so
/// nothing observable mutates until the staged commit.
pub(super) fn flat_list_heap_field_write_object(
    list: &NixList,
    source: &HeapEdgeSource,
    replacement: Value,
) -> Result<NixList, RecordOwnedHeapFieldWriteObjectError> {
    let HeapEdgeSource::ListElement { index } = source else {
        return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
    };
    let mut elements = list.clone().into_vec();
    let Some(slot) = elements.get_mut(*index) else {
        return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
    };
    *slot = replacement;
    Ok(NixList::new(elements))
}

/// Source-shape validation for a flat-attrs direct writeback target.
///
/// The flat analog of the `(Attrs, AttrBinding)` arm of
/// [`validate_direct_heap_field_write_object_source`]: a flat attrset only
/// carries `AttrBinding` fields, and the write's shape must match the
/// payload's recorded shape id.
pub(super) fn validate_flat_attrs_direct_heap_field_write_source(
    payload: &FlatAttrsPayload,
    write: &AllocationCollectorPollDirectHeapFieldWrite,
) -> Result<(), EvalHeapError> {
    if let HeapEdgeSource::AttrBinding { shape, .. } = write.source()
        && payload.metadata.shape() == *shape
    {
        return Ok(());
    }
    Err(
        EvalHeapError::CollectorPollDirectHeapFieldWriteUnsupportedSource {
            writeback_object: write.writeback_object(),
            field_index: write.field_index(),
            field_source: write.source().clone(),
        },
    )
}

/// Rewrites one entry value of staged flat-attrs entry storage.
///
/// The flat analog of [`record_owned_heap_field_write_object`]'s
/// `(Attrs, AttrBinding)` arm: shape-guarded clone-and-replace over the
/// staged entries, so nothing observable mutates until the staged commit.
pub(super) fn flat_attrs_heap_field_write_object(
    metadata: EvalHeapAttrsMetadata,
    attrs: &FlatAttrs,
    source: &HeapEdgeSource,
    replacement: Value,
) -> Result<FlatAttrs, RecordOwnedHeapFieldWriteObjectError> {
    let HeapEdgeSource::AttrBinding { shape, slot, key } = source else {
        return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
    };
    if metadata.shape() != *shape {
        return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
    }
    attrs
        .with_symbol_slot_value(*slot, *key, replacement)
        .map_err(RecordOwnedHeapFieldWriteObjectError::Attr)
}

pub(super) fn validate_direct_heap_field_write_object_source(
    object: &HeapObjectValue,
    write: &AllocationCollectorPollDirectHeapFieldWrite,
) -> Result<(), EvalHeapError> {
    if validate_captured_environment_source(object, write.source())
        .map_err(EvalHeapError::Environment)?
    {
        return Ok(());
    }
    match (object, write.source()) {
        (HeapObjectValue::List(_), HeapEdgeSource::ListElement { .. }) => Ok(()),
        (HeapObjectValue::Primop(primop), HeapEdgeSource::PrimopArgument { index })
            if *index < primop.args().len() =>
        {
            Ok(())
        }
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) if *index < lambda.with_scope_env().scopes().len() => Ok(()),
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) if *index < lambda.scoped_global_env().scopes().len() => Ok(()),
        (HeapObjectValue::Thunk(thunk), source)
            if validate_forced_thunk_cached_result_write_source(thunk, source)? =>
        {
            Ok(())
        }
        (HeapObjectValue::Thunk(thunk), source)
            if validate_parallel_thunk_payload_write_source(thunk, source)? =>
        {
            Ok(())
        }
        (HeapObjectValue::Thunk(thunk), source)
            if validate_suspended_thunk_field_write_source(thunk, source)? =>
        {
            Ok(())
        }
        _ => Err(
            EvalHeapError::CollectorPollDirectHeapFieldWriteUnsupportedSource {
                writeback_object: write.writeback_object(),
                field_index: write.field_index(),
                field_source: write.source().clone(),
            },
        ),
    }
}

pub(super) fn copied_heap_field_write_object_error(
    write: &CollectorPollCopiedHeapFieldWrite,
    error: RecordOwnedHeapFieldWriteObjectError,
) -> EvalHeapError {
    match error {
        RecordOwnedHeapFieldWriteObjectError::UnsupportedSource => {
            EvalHeapError::CollectorPollCopiedHeapFieldWriteUnsupportedSource {
                writeback_object: write.writeback_object,
                field_index: write.field_index,
                field_source: write.source.clone(),
            }
        }
        RecordOwnedHeapFieldWriteObjectError::Attr(source) => EvalHeapError::Attr(source),
        RecordOwnedHeapFieldWriteObjectError::Environment(source) => {
            EvalHeapError::Environment(source)
        }
        RecordOwnedHeapFieldWriteObjectError::Thunk(source) => EvalHeapError::Thunk(source),
        RecordOwnedHeapFieldWriteObjectError::ParallelThunkPayload(source) => {
            EvalHeapError::ParallelThunkPayload(source)
        }
    }
}

pub(super) fn direct_heap_field_write_object_error(
    write: &CollectorPollDirectHeapFieldWrite,
    error: RecordOwnedHeapFieldWriteObjectError,
) -> EvalHeapError {
    match error {
        RecordOwnedHeapFieldWriteObjectError::UnsupportedSource => {
            EvalHeapError::CollectorPollDirectHeapFieldWriteUnsupportedSource {
                writeback_object: write.writeback_object,
                field_index: write.field_index,
                field_source: write.source.clone(),
            }
        }
        RecordOwnedHeapFieldWriteObjectError::Attr(source) => EvalHeapError::Attr(source),
        RecordOwnedHeapFieldWriteObjectError::Environment(source) => {
            EvalHeapError::Environment(source)
        }
        RecordOwnedHeapFieldWriteObjectError::Thunk(source) => EvalHeapError::Thunk(source),
        RecordOwnedHeapFieldWriteObjectError::ParallelThunkPayload(source) => {
            EvalHeapError::ParallelThunkPayload(source)
        }
    }
}

pub(super) fn stage_record_owned_heap_field_write(
    object: &mut HeapObjectValue,
    source: &HeapEdgeSource,
    replacement: Value,
    environment_writebacks: &mut EnvironmentWritebackStage,
) -> Result<(), RecordOwnedHeapFieldWriteObjectError> {
    if environment_writebacks
        .stage(object, source, replacement)
        .map_err(RecordOwnedHeapFieldWriteObjectError::Environment)?
    {
        return Ok(());
    }
    *object = record_owned_heap_field_write_object(object, source, replacement)?;
    Ok(())
}

pub(super) fn record_owned_heap_field_write_object(
    object: &HeapObjectValue,
    source: &HeapEdgeSource,
    replacement: Value,
) -> Result<HeapObjectValue, RecordOwnedHeapFieldWriteObjectError> {
    match (object, source) {
        (HeapObjectValue::List(list), HeapEdgeSource::ListElement { index }) => {
            let mut elements = list.clone().into_vec();
            let Some(slot) = elements.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *slot = replacement;
            Ok(HeapObjectValue::List(NixList::new(elements)))
        }
        (HeapObjectValue::Primop(primop), HeapEdgeSource::PrimopArgument { index }) => {
            let mut args = primop.args().to_vec();
            let Some(arg) = args.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *arg = EvalPrimOpArg::new_in_module(arg.module(), arg.id(), arg.span(), replacement);
            Ok(HeapObjectValue::Primop(EvalPrimOp {
                builtin: primop.builtin(),
                symbol: primop.symbol(),
                args,
            }))
        }
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) => {
            let mut scopes = lambda.with_scope_env().scopes().to_vec();
            let Some(scope) = scopes.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *scope = EvalWithScope::new(scope.module(), scope.scope(), replacement);
            let with_env = EvalWithEnv::capture(&scopes)
                .map_err(RecordOwnedHeapFieldWriteObjectError::Environment)?;
            Ok(HeapObjectValue::Lambda(EvalLambda::with_captures(
                lambda.module(),
                lambda.pattern(),
                lambda.body(),
                lambda.frame(),
                lambda.env().clone(),
                with_env,
                lambda.scoped_global_env().clone(),
            )))
        }
        (
            HeapObjectValue::Lambda(lambda),
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Lambda,
                index,
            },
        ) => {
            let mut scopes = lambda.scoped_global_env().scopes().to_vec();
            let Some(scope) = scopes.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *scope = replacement;
            let scoped_globals = EvalScopedGlobalEnv::capture(&scopes)
                .map_err(RecordOwnedHeapFieldWriteObjectError::Environment)?;
            Ok(HeapObjectValue::Lambda(EvalLambda::with_captures(
                lambda.module(),
                lambda.pattern(),
                lambda.body(),
                lambda.frame(),
                lambda.env().clone(),
                lambda.with_scope_env().clone(),
                scoped_globals,
            )))
        }
        (HeapObjectValue::Thunk(thunk), HeapEdgeSource::ThunkCachedResult) => {
            if thunk
                .cell()
                .cached_value()
                .map_err(RecordOwnedHeapFieldWriteObjectError::Thunk)?
                .is_none()
            {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            }
            let parallel_cell = clone_parallel_thunk_cell_for_heap_field_write(thunk)?;
            if parallel_cell.is_none() {
                return Ok(HeapObjectValue::Thunk(
                    EvalThunk::with_forced_cached_result_from(thunk, replacement),
                ));
            }
            Ok(HeapObjectValue::Thunk(EvalThunk {
                kind: thunk.kind().clone(),
                cell: Arc::new(ThunkCell::forced(replacement)),
                force_storage_mode: thunk.force_storage_mode(),
                parallel_cell,
            }))
        }
        (HeapObjectValue::Thunk(thunk), HeapEdgeSource::ThunkParallelPayloadValue) => {
            let Some(parallel_cell) = thunk.parallel_payload_cell() else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            if parallel_cell
                .forced_terminal_value()
                .map_err(RecordOwnedHeapFieldWriteObjectError::ParallelThunkPayload)?
                .is_none()
            {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            }
            let parallel_cell = parallel_cell
                .relocated_forced_value(replacement)
                .map_err(RecordOwnedHeapFieldWriteObjectError::ParallelThunkPayload)?;
            Ok(HeapObjectValue::Thunk(EvalThunk {
                kind: thunk.kind().clone(),
                cell: Arc::new(
                    clone_serial_thunk_cell_for_heap_field_write(thunk.cell())
                        .map_err(RecordOwnedHeapFieldWriteObjectError::Thunk)?,
                ),
                force_storage_mode: thunk.force_storage_mode(),
                parallel_cell: Some(Arc::new(parallel_cell)),
            }))
        }
        (HeapObjectValue::Thunk(thunk), source) => {
            rewrite_suspended_thunk_field(thunk, source, replacement)
        }
        _ => Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource),
    }
}

pub(super) fn validate_suspended_thunk_field_write_source(
    thunk: &EvalThunk,
    source: &HeapEdgeSource,
) -> Result<bool, EvalHeapError> {
    thunk_supports_suspended_field_write(thunk, source).map_err(EvalHeapError::Thunk)
}

pub(super) fn validate_forced_thunk_cached_result_write_source(
    thunk: &EvalThunk,
    source: &HeapEdgeSource,
) -> Result<bool, EvalHeapError> {
    if source != &HeapEdgeSource::ThunkCachedResult {
        return Ok(false);
    }
    Ok(thunk
        .cell()
        .cached_value()
        .map_err(EvalHeapError::Thunk)?
        .is_some())
}

pub(super) fn validate_parallel_thunk_payload_write_source(
    thunk: &EvalThunk,
    source: &HeapEdgeSource,
) -> Result<bool, EvalHeapError> {
    if source != &HeapEdgeSource::ThunkParallelPayloadValue {
        return Ok(false);
    }
    Ok(thunk
        .parallel_payload_cell()
        .map(|cell| cell.forced_terminal_value())
        .transpose()?
        .flatten()
        .is_some())
}

pub(super) fn clone_serial_thunk_cell_for_heap_field_write(
    cell: &ThunkCell,
) -> Result<ThunkCell, ForceError> {
    match cell.state()? {
        ThunkState::Suspended => Ok(ThunkCell::new()),
        ThunkState::Blackhole => Err(ForceError::UnexpectedState {
            expected: ThunkState::Suspended,
            actual: ThunkState::Blackhole,
        }),
        ThunkState::Forced => Ok(ThunkCell::forced(
            cell.cached_value()?.ok_or(ForceError::MissingForcedValue)?,
        )),
    }
}

pub(super) fn clone_parallel_thunk_cell_for_heap_field_write(
    thunk: &EvalThunk,
) -> Result<Option<Arc<TreeWalkParallelThunkCell>>, RecordOwnedHeapFieldWriteObjectError> {
    thunk
        .parallel_payload_cell()
        .map(|cell| {
            cell.clone_for_relocation()
                .map(Arc::new)
                .map_err(RecordOwnedHeapFieldWriteObjectError::ParallelThunkPayload)
        })
        .transpose()
}

pub(super) fn rebuild_thunk_for_heap_field_write(
    thunk: &EvalThunk,
    kind: EvalThunkKind,
) -> Result<HeapObjectValue, RecordOwnedHeapFieldWriteObjectError> {
    Ok(HeapObjectValue::Thunk(EvalThunk {
        kind,
        cell: Arc::new(
            clone_serial_thunk_cell_for_heap_field_write(thunk.cell())
                .map_err(RecordOwnedHeapFieldWriteObjectError::Thunk)?,
        ),
        force_storage_mode: thunk.force_storage_mode(),
        parallel_cell: clone_parallel_thunk_cell_for_heap_field_write(thunk)?,
    }))
}

pub(super) fn thunk_supports_suspended_field_write(
    thunk: &EvalThunk,
    source: &HeapEdgeSource,
) -> Result<bool, ForceError> {
    if thunk.cell().state()? != ThunkState::Suspended {
        return Ok(false);
    }

    Ok(matches!(
        (thunk.kind(), source),
        (
            EvalThunkKind::Node { with_env, .. },
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Thunk,
                index,
            },
        ) if *index < with_env.scopes().len()
    ) || matches!(
        (thunk.kind(), source),
        (
            EvalThunkKind::Node { scoped_globals, .. },
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Thunk,
                index,
            },
        ) if *index < scoped_globals.scopes().len()
    ) || matches!(
        (thunk.kind(), source),
        (
            EvalThunkKind::Apply { .. },
            HeapEdgeSource::ThunkApplyFunction | HeapEdgeSource::ThunkApplyArgument,
        )
    ) || matches!(
        (thunk.kind(), source),
        (
            EvalThunkKind::Apply2 { .. },
            HeapEdgeSource::ThunkApply2Function
                | HeapEdgeSource::ThunkApply2FirstArgument
                | HeapEdgeSource::ThunkApply2SecondArgument,
        )
    ) || matches!(
        (thunk.kind(), source),
        (
            EvalThunkKind::Select { .. },
            HeapEdgeSource::ThunkSelectReceiver
        )
    ))
}

pub(super) fn rewrite_suspended_thunk_field(
    thunk: &EvalThunk,
    source: &HeapEdgeSource,
    replacement: Value,
) -> Result<HeapObjectValue, RecordOwnedHeapFieldWriteObjectError> {
    if thunk
        .cell()
        .state()
        .map_err(RecordOwnedHeapFieldWriteObjectError::Thunk)?
        != ThunkState::Suspended
    {
        return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
    }

    match (thunk.kind(), source) {
        (
            EvalThunkKind::Node {
                body,
                env,
                with_env,
                scoped_globals,
            },
            HeapEdgeSource::CapturedWithScope {
                owner: CapturedRootOwner::Thunk,
                index,
            },
        ) => {
            let mut scopes = with_env.scopes().to_vec();
            let Some(scope) = scopes.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *scope = EvalWithScope::new(scope.module(), scope.scope(), replacement);
            let with_env = EvalWithEnv::capture(&scopes)
                .map_err(RecordOwnedHeapFieldWriteObjectError::Environment)?;
            rebuild_thunk_for_heap_field_write(
                thunk,
                EvalThunkKind::Node {
                    body: *body,
                    env: env.clone(),
                    with_env,
                    scoped_globals: scoped_globals.clone(),
                },
            )
        }
        (
            EvalThunkKind::Node {
                body,
                env,
                with_env,
                scoped_globals,
            },
            HeapEdgeSource::CapturedScopedGlobal {
                owner: CapturedRootOwner::Thunk,
                index,
            },
        ) => {
            let mut scopes = scoped_globals.scopes().to_vec();
            let Some(scope) = scopes.get_mut(*index) else {
                return Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource);
            };
            *scope = replacement;
            let scoped_globals = EvalScopedGlobalEnv::capture(&scopes)
                .map_err(RecordOwnedHeapFieldWriteObjectError::Environment)?;
            rebuild_thunk_for_heap_field_write(
                thunk,
                EvalThunkKind::Node {
                    body: *body,
                    env: env.clone(),
                    with_env: with_env.clone(),
                    scoped_globals,
                },
            )
        }
        (
            EvalThunkKind::Apply {
                function,
                function_span,
                argument,
                argument_value,
                ..
            },
            HeapEdgeSource::ThunkApplyFunction,
        ) => rebuild_thunk_for_heap_field_write(
            thunk,
            EvalThunkKind::Apply {
                function: *function,
                function_span: *function_span,
                function_value: replacement,
                argument: *argument,
                argument_value: *argument_value,
            },
        ),
        (
            EvalThunkKind::Apply {
                function,
                function_span,
                function_value,
                argument,
                ..
            },
            HeapEdgeSource::ThunkApplyArgument,
        ) => rebuild_thunk_for_heap_field_write(
            thunk,
            EvalThunkKind::Apply {
                function: *function,
                function_span: *function_span,
                function_value: *function_value,
                argument: *argument,
                argument_value: replacement,
            },
        ),
        (
            EvalThunkKind::Apply2 {
                function,
                function_span,
                first_argument,
                first_argument_span,
                first_argument_value,
                second_argument,
                second_argument_span,
                second_argument_value,
                ..
            },
            HeapEdgeSource::ThunkApply2Function,
        ) => rebuild_thunk_for_heap_field_write(
            thunk,
            EvalThunkKind::Apply2 {
                function: *function,
                function_span: *function_span,
                function_value: replacement,
                first_argument: *first_argument,
                first_argument_span: *first_argument_span,
                first_argument_value: *first_argument_value,
                second_argument: *second_argument,
                second_argument_span: *second_argument_span,
                second_argument_value: *second_argument_value,
            },
        ),
        (
            EvalThunkKind::Apply2 {
                function,
                function_span,
                function_value,
                first_argument,
                first_argument_span,
                second_argument,
                second_argument_span,
                second_argument_value,
                ..
            },
            HeapEdgeSource::ThunkApply2FirstArgument,
        ) => rebuild_thunk_for_heap_field_write(
            thunk,
            EvalThunkKind::Apply2 {
                function: *function,
                function_span: *function_span,
                function_value: *function_value,
                first_argument: *first_argument,
                first_argument_span: *first_argument_span,
                first_argument_value: replacement,
                second_argument: *second_argument,
                second_argument_span: *second_argument_span,
                second_argument_value: *second_argument_value,
            },
        ),
        (
            EvalThunkKind::Apply2 {
                function,
                function_span,
                function_value,
                first_argument,
                first_argument_span,
                first_argument_value,
                second_argument,
                second_argument_span,
                ..
            },
            HeapEdgeSource::ThunkApply2SecondArgument,
        ) => rebuild_thunk_for_heap_field_write(
            thunk,
            EvalThunkKind::Apply2 {
                function: *function,
                function_span: *function_span,
                function_value: *function_value,
                first_argument: *first_argument,
                first_argument_span: *first_argument_span,
                first_argument_value: *first_argument_value,
                second_argument: *second_argument,
                second_argument_span: *second_argument_span,
                second_argument_value: replacement,
            },
        ),
        (EvalThunkKind::Select { select, path, .. }, HeapEdgeSource::ThunkSelectReceiver) => {
            rebuild_thunk_for_heap_field_write(
                thunk,
                EvalThunkKind::Select {
                    select: *select,
                    receiver: replacement,
                    path: *path,
                },
            )
        }
        _ => Err(RecordOwnedHeapFieldWriteObjectError::UnsupportedSource),
    }
}

pub(super) fn push_parallel_thunk_payload_edge(
    edges: &mut Vec<HeapEdge>,
    thunk: &EvalThunk,
) -> Result<(), EvalHeapError> {
    if let Some(value) = thunk
        .parallel_payload_cell()
        .map(|cell| cell.forced_terminal_value())
        .transpose()?
        .flatten()
    {
        push_heap_edge(edges, HeapEdgeSource::ThunkParallelPayloadValue, value)?;
    }
    Ok(())
}

pub(super) fn push_thunk_kind_edges(
    edges: &mut Vec<HeapEdge>,
    kind: &EvalThunkKind,
) -> Result<(), EvalHeapError> {
    match kind {
        EvalThunkKind::Node {
            env,
            with_env,
            scoped_globals,
            ..
        } => push_capture_edges(
            edges,
            CapturedRootOwner::Thunk,
            env,
            with_env,
            scoped_globals,
        ),
        EvalThunkKind::Apply {
            function_value,
            argument_value,
            ..
        } => {
            push_heap_edge(edges, HeapEdgeSource::ThunkApplyFunction, *function_value)?;
            push_heap_edge(edges, HeapEdgeSource::ThunkApplyArgument, *argument_value)
        }
        EvalThunkKind::Apply2 {
            function_value,
            first_argument_value,
            second_argument_value,
            ..
        } => {
            push_heap_edge(edges, HeapEdgeSource::ThunkApply2Function, *function_value)?;
            push_heap_edge(
                edges,
                HeapEdgeSource::ThunkApply2FirstArgument,
                *first_argument_value,
            )?;
            push_heap_edge(
                edges,
                HeapEdgeSource::ThunkApply2SecondArgument,
                *second_argument_value,
            )
        }
        EvalThunkKind::Select { receiver, .. } => {
            push_heap_edge(edges, HeapEdgeSource::ThunkSelectReceiver, *receiver)
        }
        EvalThunkKind::BuiltinAttr { .. } => Ok(()),
        // Only forced thunks are shed, and forced thunks scan their cached
        // result instead of their kind, so a released kind can never reach a
        // suspended/blackhole kind scan. Fail loudly if it somehow does.
        EvalThunkKind::Released => Err(EvalHeapError::ReleasedThunkWork { address: 0 }),
    }
}

pub(super) fn push_capture_edges(
    edges: &mut Vec<HeapEdge>,
    owner: CapturedRootOwner,
    env: &EvalEnv,
    with_env: &EvalWithEnv,
    scoped_globals: &EvalScopedGlobalEnv,
) -> Result<(), EvalHeapError> {
    for (frame_index, frame) in env.frames().iter().enumerate() {
        let slots = frame.slot_values()?;
        for (slot, value) in slots.into_iter().enumerate() {
            push_heap_edge(
                edges,
                HeapEdgeSource::CapturedEnv {
                    owner,
                    frame: frame_index,
                    slot,
                },
                value,
            )?;
        }
    }
    if let Some(flat) = env.flat_base() {
        push_heap_edge(
            edges,
            HeapEdgeSource::CapturedFlatEnvOwner { owner },
            flat.inline_owner(),
        )?;
    }

    for (index, scope) in with_env.scopes().iter().enumerate() {
        push_heap_edge(
            edges,
            HeapEdgeSource::CapturedWithScope { owner, index },
            scope.value(),
        )?;
    }

    for (index, value) in scoped_globals.scopes().iter().copied().enumerate() {
        push_heap_edge(
            edges,
            HeapEdgeSource::CapturedScopedGlobal { owner, index },
            value,
        )?;
    }

    Ok(())
}

//! Lambda and suspended-thunk closure serializer (RFC-0007 doc 31 §1 step 3,
//! increment 3).
//!
//! Captures the genuine closure residual the refusal census bounded — lambdas
//! plus the suspended thunks living inside their environments — and restores
//! them callable. Two identities cross the image boundary:
//!
//! - **Code** is keyed by content, never by per-process module index: a
//!   lambda's IR serializes as a [`LambdaCodeRef`] and every other
//!   module-qualified node (thunk bodies, applied functions/arguments,
//!   `with`-scope scrutinees, flat-capture allocation sites) as a
//!   [`CodeNodeRef`]. Restore re-resolves each fingerprint through the
//!   caller-supplied [`LambdaCodeResolver`] and **refuses on drift**.
//! - **Environment** is keyed into the deduplicated frame table
//!   (`env_frames`): a closure's lexical frames serialize as dense table ids;
//!   `with`-scope and scoped-global stacks are value stacks serialized inline
//!   (their `Value` words are address-free). A flat-captured environment's
//!   value tail rides the dumped arena; only its compact registry handle is
//!   re-signed after restore, once the flat-closure registry is finalized.
//!
//! Raw interned symbol ids (builtin-attr symbols) are valid in-process only;
//! see the step-3 spec's cross-process re-intern boundary.
//!
//! # Wire format
//!
//! Each closure's opaque bytes inside its [`ClosurePayload`] segment
//! (little-endian; `code_node` is a fixed-width [`CodeNodeRef`] record):
//!
//! ```text
//! closure   := own_tail_len(u32; 0xffff_ffff = no value tail) | kind(u8) | body
//! kind 0    := lambda:  lambda_code_ref(40) | frame(u32) | env_group
//! kind 1    := node thunk:   single_entry(u8) | body code_node | env_group
//! kind 2    := apply thunk:  single_entry(u8) | fn code_node | fn_span(4,4)
//!            | fn_word(8) | arg code_node | arg_word(8)
//! kind 3    := apply2 thunk: single_entry(u8) | fn code_node | fn_span | fn_word
//!            | arg1 code_node | arg1_span | arg1_word
//!            | arg2 code_node | arg2_span | arg2_word
//! kind 4    := select thunk: single_entry(u8) | sel code_node | receiver_word(8)
//!            | path(u32)
//! kind 5    := builtin-attr thunk: single_entry(u8) | symbol(u32)
//!            | version_len(u32) | version | name_len(u32) | name
//! kind 6    := collapsed forced thunk: value_word(8)
//! env_group := frame_count(u32) | frame_id(u32)*
//!            | flat_flag(u8)
//!              [ site code_node | plan_frames(u32) | owner_word(8) | tail_len(u32) ]
//!            | with_count(u32) | { scope code_node | value_word(8) }*
//!            | scoped_count(u32) | value_word(8)*
//! ```

use std::collections::HashSet;
use std::sync::Arc;

use ratchet_value::heap::{ArenaIndex, ClosurePayload, FramePayload};

use super::super::closure_code_ref::{
    CodeNodeRef, LambdaCodeDrift, LambdaCodeFingerprints, LambdaCodeRef, LambdaCodeResolver,
};
use super::super::{EvalHeap, EvalLambda, EvalThunk, EvalThunkKind, FlatClosurePayload};
use super::wire::{read_le_u32, read_le_u64, read_length_prefixed};
use super::{CapturedFrameTable, EvalHeapSnapshotError, RestoredFrameTable};
use crate::cache::CacheExprSourceHash;
use crate::compile::builtins::{PINNED_NIX_VERSION, lookup_builtin};
use crate::compile::{FrameId, IrAttrPathId};
use crate::eval::env::{
    EvalEnv, EvalFlatCapture, EvalFrame, EvalScopedGlobalEnv, EvalWithEnv, EvalWithScope,
};
use crate::eval::module::{EvalModuleId, EvalNodeRef};
use crate::eval::thunk::ThunkState;
use crate::heap::flat::FlatObjectKind;
use crate::syntax::{Span, Symbol};
use crate::value::compressed::CompressedValueWord;
use crate::value::{Value, ValueTag};

/// The `own_tail_len` wire word of a closure with no inline value tail.
const CLOSURE_TAIL_NONE: u32 = u32::MAX;

/// Wire kind tags for the closure payload body.
const KIND_LAMBDA: u8 = 0;
const KIND_NODE_THUNK: u8 = 1;
const KIND_APPLY_THUNK: u8 = 2;
const KIND_APPLY2_THUNK: u8 = 3;
const KIND_SELECT_THUNK: u8 = 4;
const KIND_BUILTIN_ATTR_THUNK: u8 = 5;
const KIND_COLLAPSED_THUNK: u8 = 6;

/// A deferred flat-environment reattachment for one restored closure.
///
/// A flat capture's value tail rides the dumped arena, but its compact
/// registry handle encodes a store index that is only stable after the
/// flat-closure registry is re-sorted into address order — so the closure is
/// first installed with a frames-only environment, and the flat base is
/// re-signed and swapped in afterwards.
struct FlatEnvFixup {
    /// The restored closure object receiving the rebuilt environment.
    index: u32,
    /// Which flat-object kind the closure resolves under.
    kind: FlatObjectKind,
    /// The closure's rebuilt lexical frames (outermost to innermost).
    frames: Vec<Arc<EvalFrame>>,
    /// The resolved flat-capture allocation site.
    site: EvalNodeRef,
    /// The conceptual frame depth at the allocation site.
    plan_frames: u32,
    /// The closure value owning the inline value tail.
    owner: Value,
    /// The owner's tail length (also the capture-plan value count).
    tail_len: u32,
}

/// One decoded environment group, before frame-table resolution.
struct DecodedEnvGroup {
    frame_ids: Vec<u32>,
    flat: Option<DecodedFlatBase>,
    with_scopes: Vec<(CodeNodeRef, u64)>,
    scoped_globals: Vec<u64>,
}

/// The decoded flat-capture section of an environment group.
struct DecodedFlatBase {
    site: CodeNodeRef,
    plan_frames: u32,
    owner_word: u64,
    tail_len: u32,
}

impl EvalHeap {
    /// Captures the frame table and every lambda / suspended thunk as closure
    /// payloads (the increment-3 capture half).
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::UnsnapshottableThunkState`] for a
    /// forced, in-flight, poisoned, or released thunk (the mutating collapse
    /// is increment 4), [`EvalHeapSnapshotError::UnsnapshottableClosures`] for
    /// a thunk with parallel force storage,
    /// [`EvalHeapSnapshotError::CodeFingerprintUnavailable`] when a referenced
    /// module cannot be fingerprinted, and capture-side frame-table errors.
    pub(super) fn capture_closure_payloads(
        &self,
        code: &dyn LambdaCodeFingerprints,
    ) -> Result<(Vec<FramePayload>, Vec<ClosurePayload>), EvalHeapSnapshotError> {
        let frame_table = self.capture_env_frame_table()?;
        let mut payloads = Vec::new();
        for object in self.flat_closures.iter() {
            let index = self
                .flat_arena
                .index_for_pointer(object.ptr())
                .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?
                .raw();
            let (bytes, kind) = match object.object().payload() {
                FlatClosurePayload::Thunk(thunk) => (
                    encode_thunk(index, thunk, &frame_table, code)?,
                    FlatObjectKind::Thunk,
                ),
                FlatClosurePayload::SharedThunk(thunk) => (
                    encode_thunk(index, thunk, &frame_table, code)?,
                    FlatObjectKind::Thunk,
                ),
                FlatClosurePayload::Lambda(lambda) => (
                    encode_lambda(index, lambda, &frame_table, code)?,
                    FlatObjectKind::Lambda,
                ),
                // Primops ride their own v5 segment; retired slots hold plain
                // tag data that restores verbatim from the dumped bytes.
                FlatClosurePayload::Primop(_) | FlatClosurePayload::Retired(_) => continue,
            };
            let tail_len = match self
                .flat_closures
                .value_tail(object.ptr(), kind)
                .map_err(EvalHeapSnapshotError::FlatResolve)?
            {
                Some(values) => values.len() as u32,
                None => CLOSURE_TAIL_NONE,
            };
            let mut closure_bytes = Vec::with_capacity(4 + bytes.len());
            closure_bytes.extend_from_slice(&tail_len.to_le_bytes());
            closure_bytes.extend_from_slice(&bytes);
            payloads.push(ClosurePayload {
                index,
                closure_bytes,
            });
        }
        Ok((frame_table.into_payloads(), payloads))
    }

    /// Restores every closure payload over the rebuilt frame table, then
    /// finalizes the flat-closure registry and re-signs flat-capture handles.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapSnapshotError::DuplicateObjectIndex`] for a repeated
    /// arena index, [`EvalHeapSnapshotError::MalformedClosurePayload`] for
    /// bytes that do not decode (or a flat fixup that does not re-sign),
    /// [`EvalHeapSnapshotError::ClosureCodeDrift`] when a code fingerprint is
    /// absent from the resolver, and the primop-style registry errors for
    /// builtin-attr thunks.
    pub(super) fn restore_closure_payloads(
        &mut self,
        payloads: &[ClosurePayload],
        frame_table: &RestoredFrameTable,
        resolver: &dyn LambdaCodeResolver,
        remap: Option<&super::reintern::IdentityRemap>,
        seen: &mut HashSet<u32>,
    ) -> Result<(), EvalHeapSnapshotError> {
        let mut fixups: Vec<FlatEnvFixup> = Vec::new();
        let mut tail_checks: Vec<(ArenaIndex, FlatObjectKind, u32)> = Vec::new();
        for payload in payloads {
            if !seen.insert(payload.index) {
                return Err(EvalHeapSnapshotError::DuplicateObjectIndex {
                    index: payload.index,
                });
            }
            self.restore_one_closure(
                payload,
                frame_table,
                resolver,
                remap,
                &mut fixups,
                &mut tail_checks,
            )?;
        }
        // Primop and closure segments each restore in their own capture order,
        // so the shared flat-closure registry is interleaved out of address
        // order until this sort; tail resolution (the checks and handle
        // signing below) binary-searches the registry and depends on it.
        self.flat_closures.finalize_restored_registry();
        for (index, kind, own_tail_len) in tail_checks {
            // The dumped header's tail length must agree with the declared
            // extent, or handle signing would validate against a lie.
            let ptr = self
                .flat_arena
                .pointer_for_index(index)
                .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
            let tail = self
                .flat_closures
                .value_tail(ptr, kind)
                .map_err(EvalHeapSnapshotError::FlatResolve)?;
            if tail.map(<[Value]>::len) != Some(own_tail_len as usize) {
                return Err(EvalHeapSnapshotError::MalformedClosurePayload { index: index.raw() });
            }
        }
        for fixup in fixups {
            self.apply_flat_env_fixup(fixup)?;
        }
        Ok(())
    }

    /// Decodes and installs one closure payload (without its flat base).
    fn restore_one_closure(
        &mut self,
        payload: &ClosurePayload,
        frame_table: &RestoredFrameTable,
        resolver: &dyn LambdaCodeResolver,
        remap: Option<&super::reintern::IdentityRemap>,
        fixups: &mut Vec<FlatEnvFixup>,
        tail_checks: &mut Vec<(ArenaIndex, FlatObjectKind, u32)>,
    ) -> Result<(), EvalHeapSnapshotError> {
        let index = payload.index;
        let malformed = || EvalHeapSnapshotError::MalformedClosurePayload { index };
        let drift = |error: LambdaCodeDrift| drift_error(index, error);
        let ptr = self
            .flat_arena
            .pointer_for_index(ArenaIndex::new(index))
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        let bytes = &payload.closure_bytes;
        let mut cursor = 0usize;
        let own_tail_len = read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?;
        let kind_byte = *bytes.get(cursor).ok_or_else(malformed)?;
        cursor += 1;

        let (flat_payload, kind, deferred_flat) = match kind_byte {
            KIND_LAMBDA => {
                let code_ref = LambdaCodeRef::read(bytes, &mut cursor).map_err(drift)?;
                let frame = read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?;
                let resolved = code_ref.resolve(resolver).map_err(drift)?;
                let group = decode_env_group(bytes, &mut cursor, index)?;
                let (env, with_env, scoped_globals, frames) =
                    resolve_env_group(&group, frame_table, resolver, index)?;
                let lambda = EvalLambda::with_captures(
                    resolved.module,
                    resolved.pattern,
                    resolved.body,
                    FrameId::new(frame),
                    env,
                    with_env,
                    scoped_globals,
                );
                (
                    FlatClosurePayload::Lambda(lambda),
                    FlatObjectKind::Lambda,
                    group.flat.map(|flat| (flat, frames)),
                )
            }
            KIND_NODE_THUNK => {
                let single_entry = read_bool(bytes, &mut cursor).ok_or_else(malformed)?;
                let body = CodeNodeRef::read(bytes, &mut cursor).map_err(drift)?;
                let (module, body_ir) = body.resolve(resolver).map_err(drift)?;
                let group = decode_env_group(bytes, &mut cursor, index)?;
                let (env, with_env, scoped_globals, frames) =
                    resolve_env_group(&group, frame_table, resolver, index)?;
                let mut thunk =
                    EvalThunk::with_captures(module, body_ir, env, with_env, scoped_globals);
                if single_entry {
                    thunk = thunk.into_single_entry();
                }
                (
                    FlatClosurePayload::Thunk(thunk),
                    FlatObjectKind::Thunk,
                    group.flat.map(|flat| (flat, frames)),
                )
            }
            KIND_APPLY_THUNK => {
                let single_entry = read_bool(bytes, &mut cursor).ok_or_else(malformed)?;
                let function = CodeNodeRef::read(bytes, &mut cursor).map_err(drift)?;
                let function_span = read_span(bytes, &mut cursor).ok_or_else(malformed)?;
                let function_value = read_word(bytes, &mut cursor).ok_or_else(malformed)?;
                let argument = CodeNodeRef::read(bytes, &mut cursor).map_err(drift)?;
                let argument_value = read_word(bytes, &mut cursor).ok_or_else(malformed)?;
                let (fn_module, fn_ir) = function.resolve(resolver).map_err(drift)?;
                let (arg_module, arg_ir) = argument.resolve(resolver).map_err(drift)?;
                let mut thunk = EvalThunk::apply(
                    fn_module,
                    fn_ir,
                    function_span,
                    function_value,
                    arg_module,
                    arg_ir,
                    argument_value,
                );
                if single_entry {
                    thunk = thunk.into_single_entry();
                }
                (
                    FlatClosurePayload::Thunk(thunk),
                    FlatObjectKind::Thunk,
                    None,
                )
            }
            KIND_APPLY2_THUNK => {
                let single_entry = read_bool(bytes, &mut cursor).ok_or_else(malformed)?;
                let function = CodeNodeRef::read(bytes, &mut cursor).map_err(drift)?;
                let function_span = read_span(bytes, &mut cursor).ok_or_else(malformed)?;
                let function_value = read_word(bytes, &mut cursor).ok_or_else(malformed)?;
                let first = CodeNodeRef::read(bytes, &mut cursor).map_err(drift)?;
                let first_span = read_span(bytes, &mut cursor).ok_or_else(malformed)?;
                let first_value = read_word(bytes, &mut cursor).ok_or_else(malformed)?;
                let second = CodeNodeRef::read(bytes, &mut cursor).map_err(drift)?;
                let second_span = read_span(bytes, &mut cursor).ok_or_else(malformed)?;
                let second_value = read_word(bytes, &mut cursor).ok_or_else(malformed)?;
                let (fn_module, fn_ir) = function.resolve(resolver).map_err(drift)?;
                let (first_module, first_ir) = first.resolve(resolver).map_err(drift)?;
                let (second_module, second_ir) = second.resolve(resolver).map_err(drift)?;
                let mut thunk = EvalThunk::apply2(
                    fn_module,
                    fn_ir,
                    function_span,
                    function_value,
                    first_module,
                    first_ir,
                    first_span,
                    first_value,
                    second_module,
                    second_ir,
                    second_span,
                    second_value,
                );
                if single_entry {
                    thunk = thunk.into_single_entry();
                }
                (
                    FlatClosurePayload::Thunk(thunk),
                    FlatObjectKind::Thunk,
                    None,
                )
            }
            KIND_SELECT_THUNK => {
                let single_entry = read_bool(bytes, &mut cursor).ok_or_else(malformed)?;
                let select = CodeNodeRef::read(bytes, &mut cursor).map_err(drift)?;
                let receiver = read_word(bytes, &mut cursor).ok_or_else(malformed)?;
                let path = read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?;
                let (module, select_ir) = select.resolve(resolver).map_err(drift)?;
                let mut thunk =
                    EvalThunk::select(module, select_ir, receiver, IrAttrPathId::new(path));
                if single_entry {
                    thunk = thunk.into_single_entry();
                }
                (
                    FlatClosurePayload::Thunk(thunk),
                    FlatObjectKind::Thunk,
                    None,
                )
            }
            KIND_COLLAPSED_THUNK => {
                // A collapsed forced thunk restores as a released forced
                // wrapper: forcing it replays the cached value, and its shed
                // deferred work and captures are gone by construction.
                let value = read_word(bytes, &mut cursor).ok_or_else(malformed)?;
                (
                    FlatClosurePayload::Thunk(EvalThunk::released_forced(value)),
                    FlatObjectKind::Thunk,
                    None,
                )
            }
            KIND_BUILTIN_ATTR_THUNK => {
                let single_entry = read_bool(bytes, &mut cursor).ok_or_else(malformed)?;
                let symbol = Symbol::new(read_le_u32(bytes, &mut cursor).ok_or_else(malformed)?);
                // W1 cross-evaluator re-intern of the raw diagnostic symbol.
                let symbol = match remap.filter(|remap| !remap.is_identity()) {
                    Some(remap) => remap.symbol(symbol).ok_or_else(malformed)?,
                    None => symbol,
                };
                let version = read_length_prefixed(bytes, &mut cursor).ok_or_else(malformed)?;
                if version.as_slice() != PINNED_NIX_VERSION {
                    return Err(EvalHeapSnapshotError::RegistryVersionMismatch {
                        expected: PINNED_NIX_VERSION.to_vec(),
                        found: version,
                    });
                }
                let name = read_length_prefixed(bytes, &mut cursor).ok_or_else(malformed)?;
                let builtin =
                    lookup_builtin(&name).ok_or(EvalHeapSnapshotError::UnknownBuiltin { name })?;
                let mut thunk = EvalThunk::builtin_attr(symbol, builtin);
                if single_entry {
                    thunk = thunk.into_single_entry();
                }
                (
                    FlatClosurePayload::Thunk(thunk),
                    FlatObjectKind::Thunk,
                    None,
                )
            }
            _ => return Err(malformed()),
        };
        if cursor != bytes.len() {
            return Err(malformed());
        }

        if own_tail_len == CLOSURE_TAIL_NONE {
            self.flat_closures
                .restore_payload(ptr, kind, flat_payload)
                .map_err(EvalHeapSnapshotError::FlatResolve)?;
        } else {
            self.flat_closures
                .restore_payload_with_value_tail(ptr, kind, flat_payload, own_tail_len as usize)
                .map_err(EvalHeapSnapshotError::FlatResolve)?;
            // The header-length sanity check runs after the registry finalize
            // (tail resolution binary-searches the registry by address).
            tail_checks.push((ArenaIndex::new(index), kind, own_tail_len));
        }

        if let Some((flat, frames)) = deferred_flat {
            let site = flat.site.resolve(resolver).map_err(drift)?;
            fixups.push(FlatEnvFixup {
                index,
                kind,
                frames,
                site: EvalNodeRef::new(site.0, site.1),
                plan_frames: flat.plan_frames,
                owner: decode_value(flat.owner_word).ok_or_else(malformed)?,
                tail_len: flat.tail_len,
            });
        }
        Ok(())
    }

    /// Re-signs one flat-capture handle and swaps the full environment in.
    fn apply_flat_env_fixup(&mut self, fixup: FlatEnvFixup) -> Result<(), EvalHeapSnapshotError> {
        let malformed = || EvalHeapSnapshotError::MalformedClosurePayload { index: fixup.index };
        let owner_ptr = match fixup.owner.tag() {
            ValueTag::Thunk => fixup.owner.as_thunk_ptr(),
            ValueTag::Lambda => fixup.owner.as_lambda_ptr(),
            _ => return Err(malformed()),
        }
        .map_err(|_| malformed())?;
        let store_index = self
            .flat_closures
            .value_tail_store_index(owner_ptr)
            .ok_or_else(malformed)?;
        let handle = self
            .flat_closures
            .value_tail_handle_at(store_index, owner_ptr, fixup.tail_len as usize)
            .map_err(|_| malformed())?;
        let flat_base =
            EvalFlatCapture::inline(fixup.site, fixup.plan_frames as usize, fixup.owner, handle);
        let env = EvalEnv::restore_parts(&fixup.frames, Some(flat_base))
            .map_err(EvalHeapSnapshotError::EnvFrameUnreadable)?;
        let ptr = self
            .flat_arena
            .pointer_for_index(ArenaIndex::new(fixup.index))
            .ok_or(EvalHeapSnapshotError::ObjectOutsideReservation)?;
        let payload = self
            .flat_closures
            .resolve_mut(ptr, fixup.kind)
            .map_err(EvalHeapSnapshotError::FlatResolve)?;
        let replaced = match payload {
            FlatClosurePayload::Lambda(lambda) => {
                lambda.replace_env(env);
                true
            }
            FlatClosurePayload::Thunk(thunk) => thunk.replace_node_env(env),
            _ => false,
        };
        if !replaced {
            return Err(malformed());
        }
        Ok(())
    }
}

/// Maps a code-reference failure to the payload-scoped snapshot error.
fn drift_error(index: u32, error: LambdaCodeDrift) -> EvalHeapSnapshotError {
    match error {
        LambdaCodeDrift::Malformed => EvalHeapSnapshotError::MalformedClosurePayload { index },
        LambdaCodeDrift::SourceMissing => EvalHeapSnapshotError::ClosureCodeDrift { index },
    }
}

/// Encodes one lambda closure body (kind byte included).
fn encode_lambda(
    index: u32,
    lambda: &EvalLambda,
    frames: &CapturedFrameTable,
    code: &dyn LambdaCodeFingerprints,
) -> Result<Vec<u8>, EvalHeapSnapshotError> {
    let code_ref = LambdaCodeRef {
        source_hash: fingerprint(code, lambda.module())?,
        pattern: lambda.pattern(),
        body: lambda.body(),
    };
    let mut out = Vec::new();
    out.push(KIND_LAMBDA);
    out.extend_from_slice(&code_ref.to_bytes());
    out.extend_from_slice(&lambda.frame().as_u32().to_le_bytes());
    encode_env_group(
        &mut out,
        index,
        lambda.env(),
        lambda.with_scope_env(),
        lambda.scoped_global_env(),
        frames,
        code,
    )?;
    Ok(out)
}

/// Encodes one suspended thunk closure body (kind byte included).
fn encode_thunk(
    index: u32,
    thunk: &EvalThunk,
    frames: &CapturedFrameTable,
    code: &dyn LambdaCodeFingerprints,
) -> Result<Vec<u8>, EvalHeapSnapshotError> {
    if !thunk.has_serial_only_force_storage() && !thunk.is_single_entry_force_storage() {
        return Err(EvalHeapSnapshotError::UnsnapshottableClosures { count: 1 });
    }
    match thunk.cell().state() {
        Ok(ThunkState::Suspended) => {}
        // A forced thunk *is* its cached value: serialize the value word alone
        // (the collapsed-thunk payload, increment 4) and restore a released
        // forced wrapper. A cached value that is itself a thunk is a collapse
        // chain and refuses — the census's 0-chain measurement is empirical,
        // not an invariant.
        Ok(ThunkState::Forced) => {
            return match thunk.cell().cached_value() {
                Ok(Some(value)) if value.tag() == crate::value::ValueTag::Thunk => {
                    Err(EvalHeapSnapshotError::ForcedThunkChain { index })
                }
                Ok(Some(value)) => {
                    let mut out = Vec::with_capacity(9);
                    out.push(KIND_COLLAPSED_THUNK);
                    encode_word(&mut out, value);
                    Ok(out)
                }
                _ => Err(EvalHeapSnapshotError::UnsnapshottableThunkState { index }),
            };
        }
        // An in-flight or poisoned cell is not a stable value.
        Ok(ThunkState::Blackhole) | Err(_) => {
            return Err(EvalHeapSnapshotError::UnsnapshottableThunkState { index });
        }
    }
    let single_entry = u8::from(thunk.is_single_entry_force_storage());
    let mut out = Vec::new();
    match thunk.kind() {
        EvalThunkKind::Node {
            body,
            env,
            dynamic_env,
        } => {
            let (with_env, scoped_globals) = match dynamic_env.as_deref() {
                Some(dynamic) => (&dynamic.with_env, &dynamic.scoped_globals),
                None => (EvalWithEnv::empty_ref(), EvalScopedGlobalEnv::empty_ref()),
            };
            out.push(KIND_NODE_THUNK);
            out.push(single_entry);
            out.extend_from_slice(&node_ref(code, *body)?.to_bytes());
            encode_env_group(&mut out, index, env, with_env, scoped_globals, frames, code)?;
        }
        EvalThunkKind::Apply {
            function,
            function_span,
            function_value,
            argument,
            argument_value,
        } => {
            out.push(KIND_APPLY_THUNK);
            out.push(single_entry);
            out.extend_from_slice(&node_ref(code, *function)?.to_bytes());
            encode_span(&mut out, *function_span);
            encode_word(&mut out, *function_value);
            out.extend_from_slice(&node_ref(code, *argument)?.to_bytes());
            encode_word(&mut out, *argument_value);
        }
        EvalThunkKind::Apply2 {
            function,
            function_span,
            function_value,
            first_argument,
            first_argument_span,
            first_argument_value,
            second_argument,
            second_argument_span,
            second_argument_value,
        } => {
            out.push(KIND_APPLY2_THUNK);
            out.push(single_entry);
            out.extend_from_slice(&node_ref(code, *function)?.to_bytes());
            encode_span(&mut out, *function_span);
            encode_word(&mut out, *function_value);
            out.extend_from_slice(&node_ref(code, *first_argument)?.to_bytes());
            encode_span(&mut out, *first_argument_span);
            encode_word(&mut out, *first_argument_value);
            out.extend_from_slice(&node_ref(code, *second_argument)?.to_bytes());
            encode_span(&mut out, *second_argument_span);
            encode_word(&mut out, *second_argument_value);
        }
        EvalThunkKind::Select {
            select,
            receiver,
            path,
        } => {
            out.push(KIND_SELECT_THUNK);
            out.push(single_entry);
            out.extend_from_slice(&node_ref(code, *select)?.to_bytes());
            encode_word(&mut out, *receiver);
            out.extend_from_slice(&path.as_u32().to_le_bytes());
        }
        EvalThunkKind::BuiltinAttr { symbol, builtin } => {
            out.push(KIND_BUILTIN_ATTR_THUNK);
            out.push(single_entry);
            out.extend_from_slice(&symbol.as_u32().to_le_bytes());
            out.extend_from_slice(&(PINNED_NIX_VERSION.len() as u32).to_le_bytes());
            out.extend_from_slice(PINNED_NIX_VERSION);
            let name = builtin.name();
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            out.extend_from_slice(name);
        }
        // A released thunk shed its deferred work after forcing; it is
        // forced by definition and collapses in increment 4.
        EvalThunkKind::Released => {
            return Err(EvalHeapSnapshotError::UnsnapshottableThunkState { index });
        }
    }
    Ok(out)
}

/// Resolves a decoded env group into runtime captures (flat base deferred).
#[allow(clippy::type_complexity)]
fn resolve_env_group(
    group: &DecodedEnvGroup,
    frame_table: &RestoredFrameTable,
    resolver: &dyn LambdaCodeResolver,
    index: u32,
) -> Result<
    (
        EvalEnv,
        EvalWithEnv,
        EvalScopedGlobalEnv,
        Vec<Arc<EvalFrame>>,
    ),
    EvalHeapSnapshotError,
> {
    let malformed = || EvalHeapSnapshotError::MalformedClosurePayload { index };
    let mut frames = Vec::with_capacity(group.frame_ids.len());
    for id in &group.frame_ids {
        frames.push(Arc::clone(frame_table.frame(*id).ok_or_else(malformed)?));
    }
    let env =
        EvalEnv::restore_parts(&frames, None).map_err(EvalHeapSnapshotError::EnvFrameUnreadable)?;
    let mut with_scopes = Vec::with_capacity(group.with_scopes.len());
    for (scope_ref, word) in &group.with_scopes {
        let (module, scope_ir) = scope_ref
            .resolve(resolver)
            .map_err(|error| drift_error(index, error))?;
        let value = decode_value(*word).ok_or_else(malformed)?;
        with_scopes.push(EvalWithScope::new(module, scope_ir, value));
    }
    let mut scoped = Vec::with_capacity(group.scoped_globals.len());
    for word in &group.scoped_globals {
        scoped.push(decode_value(*word).ok_or_else(malformed)?);
    }
    Ok((
        env,
        EvalWithEnv::from(with_scopes),
        EvalScopedGlobalEnv::from(scoped),
        frames,
    ))
}

/// Fingerprints `module`, refusing capture when its identity is unavailable.
fn fingerprint(
    code: &dyn LambdaCodeFingerprints,
    module: EvalModuleId,
) -> Result<CacheExprSourceHash, EvalHeapSnapshotError> {
    code.fingerprint(module)
        .ok_or(EvalHeapSnapshotError::CodeFingerprintUnavailable {
            module: module.as_u32(),
        })
}

/// Builds a content-keyed reference for one module-qualified node.
fn node_ref(
    code: &dyn LambdaCodeFingerprints,
    node: EvalNodeRef,
) -> Result<CodeNodeRef, EvalHeapSnapshotError> {
    Ok(CodeNodeRef {
        source_hash: fingerprint(code, node.module())?,
        node: node.id(),
    })
}

/// Serializes one environment group (see the module wire format).
fn encode_env_group(
    out: &mut Vec<u8>,
    index: u32,
    env: &EvalEnv,
    with_env: &EvalWithEnv,
    scoped_globals: &EvalScopedGlobalEnv,
    frames: &CapturedFrameTable,
    code: &dyn LambdaCodeFingerprints,
) -> Result<(), EvalHeapSnapshotError> {
    let view = env.frames();
    out.extend_from_slice(&(view.len() as u32).to_le_bytes());
    for frame in view.iter() {
        let id = frames
            .frame_id(frame)
            .ok_or(EvalHeapSnapshotError::MalformedClosurePayload { index })?;
        out.extend_from_slice(&id.to_le_bytes());
    }
    match env.flat_base() {
        Some(flat) => {
            out.push(1);
            out.extend_from_slice(&node_ref(code, flat.allocation_site())?.to_bytes());
            out.extend_from_slice(&(flat.frame_count() as u32).to_le_bytes());
            encode_word(out, flat.inline_owner());
            out.extend_from_slice(&(flat.tail_handle().len() as u32).to_le_bytes());
        }
        None => out.push(0),
    }
    out.extend_from_slice(&(with_env.scopes().len() as u32).to_le_bytes());
    for scope in with_env.scopes() {
        out.extend_from_slice(&node_ref(code, scope.scope_ref())?.to_bytes());
        encode_word(out, scope.value());
    }
    out.extend_from_slice(&(scoped_globals.scopes().len() as u32).to_le_bytes());
    for value in scoped_globals.scopes() {
        encode_word(out, *value);
    }
    Ok(())
}

/// Parses one environment group at `*cursor`.
fn decode_env_group(
    bytes: &[u8],
    cursor: &mut usize,
    index: u32,
) -> Result<DecodedEnvGroup, EvalHeapSnapshotError> {
    let malformed = || EvalHeapSnapshotError::MalformedClosurePayload { index };
    let frame_count = read_le_u32(bytes, cursor).ok_or_else(malformed)? as usize;
    // Untrusted counts: fail on truncation as the cursor advances rather
    // than pre-reserving a lying capacity.
    let mut frame_ids = Vec::new();
    for _ in 0..frame_count {
        frame_ids.push(read_le_u32(bytes, cursor).ok_or_else(malformed)?);
    }
    let flat = match bytes.get(*cursor).copied() {
        Some(0) => {
            *cursor += 1;
            None
        }
        Some(1) => {
            *cursor += 1;
            let site = CodeNodeRef::read(bytes, cursor).map_err(|_| malformed())?;
            let plan_frames = read_le_u32(bytes, cursor).ok_or_else(malformed)?;
            let owner_word = read_le_u64(bytes, cursor).ok_or_else(malformed)?;
            let tail_len = read_le_u32(bytes, cursor).ok_or_else(malformed)?;
            Some(DecodedFlatBase {
                site,
                plan_frames,
                owner_word,
                tail_len,
            })
        }
        _ => return Err(malformed()),
    };
    let with_count = read_le_u32(bytes, cursor).ok_or_else(malformed)? as usize;
    let mut with_scopes = Vec::new();
    for _ in 0..with_count {
        let scope = CodeNodeRef::read(bytes, cursor).map_err(|_| malformed())?;
        let word = read_le_u64(bytes, cursor).ok_or_else(malformed)?;
        with_scopes.push((scope, word));
    }
    let scoped_count = read_le_u32(bytes, cursor).ok_or_else(malformed)? as usize;
    let mut scoped_globals = Vec::new();
    for _ in 0..scoped_count {
        scoped_globals.push(read_le_u64(bytes, cursor).ok_or_else(malformed)?);
    }
    Ok(DecodedEnvGroup {
        frame_ids,
        flat,
        with_scopes,
        scoped_globals,
    })
}

/// Appends one address-free Candidate-C value word.
fn encode_word(out: &mut Vec<u8>, value: Value) {
    out.extend_from_slice(&value.word().raw().to_le_bytes());
}

/// Appends one span as `start(u32) | end(u32)`.
fn encode_span(out: &mut Vec<u8>, span: Span) {
    out.extend_from_slice(&span.start.to_le_bytes());
    out.extend_from_slice(&span.end.to_le_bytes());
}

/// Reads a span at `*cursor`, advancing it, or `None` if truncated.
fn read_span(bytes: &[u8], cursor: &mut usize) -> Option<Span> {
    let start = read_le_u32(bytes, cursor)?;
    let end = read_le_u32(bytes, cursor)?;
    Some(Span::new(start, end))
}

/// Reads one `0`/`1` byte at `*cursor`; any other byte is malformed.
fn read_bool(bytes: &[u8], cursor: &mut usize) -> Option<bool> {
    let byte = *bytes.get(*cursor)?;
    *cursor += 1;
    match byte {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// Reads and decodes one value word at `*cursor`, or `None` if invalid.
fn read_word(bytes: &[u8], cursor: &mut usize) -> Option<Value> {
    decode_value(read_le_u64(bytes, cursor)?)
}

/// Decodes one raw word into a runtime value, or `None` if invalid.
fn decode_value(raw: u64) -> Option<Value> {
    CompressedValueWord::from_raw(raw)
        .ok()
        .map(Value::from_word)
}

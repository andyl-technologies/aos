//! Read-only compact-destination projection at a complete mutator-root boundary.
//!
//! The probe reuses the precise weak-root traversal and then sizes a hypothetical
//! evacuation destination. It never copies or retains a [`Value`], mutates the
//! heap, or treats hash-cons tables as roots. The model intentionally reports a
//! lower and upper heap image: both use 8-byte stable thunk heads and packed
//! collections, while the upper charges conservative typed-work records and
//! closure bodies. Captured lexical frames are a separate named-state component.
//!
//! The projection is a falsifier, not an allocator design. In particular, it
//! assumes source code remains outside the named-state budget, weak indexes are
//! rebuilt after evacuation, and the import-boundary root publisher accounts for
//! every live evaluator local. Unknown record-table payloads remain explicitly
//! unattributed rather than silently receiving a compact layout.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use crate::eval::env::{EvalEnv, EvalFrame};
use crate::eval::thunk::ThunkState;

use super::*;

const MIB: u64 = 1024 * 1024;
const HEAP_GATE_BYTES: u64 = 77_600 * MIB / 1000;
const NAMED_STATE_GATE_BYTES: u64 = 92_609 * MIB / 1000;
const FRONTEND_ALLOWANCE_BYTES: u64 = 4 * 1024 * 1024;
const WEAK_INDEX_ALLOWANCE_BYTES: u64 = 8 * 1024 * 1024;
const UNATTRIBUTED_GATE_BYTES: u64 = 8 * 1024 * 1024;

/// Lower/upper byte projection for one compact object class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProjectedKind {
    count: u64,
    current_bytes: u64,
    compact_lower_bytes: u64,
    compact_upper_bytes: u64,
}

impl ProjectedKind {
    fn add(&mut self, current: usize, lower: u64, upper: u64) {
        self.count = self.count.saturating_add(1);
        self.current_bytes = self.current_bytes.saturating_add(current as u64);
        self.compact_lower_bytes = self.compact_lower_bytes.saturating_add(lower);
        self.compact_upper_bytes = self.compact_upper_bytes.saturating_add(upper.max(lower));
    }
}

/// A read-only compact evacuation-destination size projection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CompactDestinationProjection {
    roots: u64,
    reachable_objects: u64,
    strings_paths: ProjectedKind,
    lists: ProjectedKind,
    attrs: ProjectedKind,
    thunk_heads: ProjectedKind,
    typed_work: ProjectedKind,
    lambdas: ProjectedKind,
    primops: ProjectedKind,
    captured_frames: u64,
    captured_frame_slots: u64,
    packed_frame_bytes: u64,
    packed_dynamic_scope_upper_bytes: u64,
    weak_index_entries: u64,
    rebuilt_weak_index_bytes: u64,
    unattributed_objects: u64,
    unattributed_current_bytes: u64,
}

impl CompactDestinationProjection {
    fn heap_lower_bytes(&self) -> u64 {
        self.kinds().map(|kind| kind.compact_lower_bytes).sum()
    }

    fn heap_upper_bytes(&self) -> u64 {
        self.kinds().map(|kind| kind.compact_upper_bytes).sum()
    }

    fn named_state_upper_bytes(&self) -> u64 {
        self.heap_upper_bytes()
            .saturating_add(self.packed_frame_bytes)
            .saturating_add(self.packed_dynamic_scope_upper_bytes)
            .saturating_add(FRONTEND_ALLOWANCE_BYTES)
            .saturating_add(WEAK_INDEX_ALLOWANCE_BYTES)
            .saturating_add(self.unattributed_current_bytes)
    }

    fn kinds(&self) -> impl Iterator<Item = ProjectedKind> {
        [
            self.strings_paths,
            self.lists,
            self.attrs,
            self.thunk_heads,
            self.typed_work,
            self.lambdas,
            self.primops,
        ]
        .into_iter()
    }
}

impl fmt::Display for CompactDestinationProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = |f: &mut fmt::Formatter<'_>, name: &str, value: ProjectedKind| {
            write!(
                f,
                "\"{name}\":[{},{},{},{}]",
                value.count,
                value.current_bytes,
                value.compact_lower_bytes,
                value.compact_upper_bytes
            )
        };
        write!(
            f,
            "{{\"roots\":{},\"reachable_objects\":{},\
             \"kind_tuple\":\"exact_count,observed_current_bytes,assumed_compact_lower_bytes,\
             assumed_compact_upper_bytes\",\"kinds\":{{",
            self.roots, self.reachable_objects
        )?;
        kind(f, "strings_paths", self.strings_paths)?;
        write!(f, ",")?;
        kind(f, "lists", self.lists)?;
        write!(f, ",")?;
        kind(f, "attrs", self.attrs)?;
        write!(f, ",")?;
        kind(f, "thunk_heads", self.thunk_heads)?;
        write!(f, ",")?;
        kind(f, "typed_work", self.typed_work)?;
        write!(f, ",")?;
        kind(f, "lambdas", self.lambdas)?;
        write!(f, ",")?;
        kind(f, "primops", self.primops)?;
        write!(
            f,
            "}},\"frames\":{{\"exact_distinct_count\":{},\"exact_slot_count\":{},\
             \"assumed_packed_bytes\":{},\"dynamic_scope_upper_bytes\":{}}},\
             \"weak_indexes\":{{\"entries\":{},\"projected_bytes\":{},\
             \"allowance_bytes\":{},\"within_allowance\":{}}},\
             \"unattributed\":{{\"exact_objects\":{},\"observed_current_bytes\":{},\
             \"gate_bytes\":{},\"within_gate\":{}}},\
             \"totals\":{{\"heap_lower_bytes\":{},\"heap_upper_bytes\":{},\
             \"heap_gate_bytes\":{},\"heap_upper_pass\":{},\
             \"frontend_allowance_bytes\":{},\"named_state_upper_bytes\":{},\
             \"named_state_gate_bytes\":{},\"named_state_upper_pass\":{}}},\
             \"assumptions\":{{\"root_contract\":\"import_boundary_mutator_root_set\",\
             \"measurement_scope\":\"reachable store objects; current bytes are inline arena \
             extents plus list spines and exclude allocator metadata\",\
             \"thunk_head_bytes\":8,\"values_are_compact_words\":true,\
             \"typed_work_is_kind_pooled\":true,\"collections_are_exact_length\":true,\
             \"frames_are_parent_slot_packed\":true,\
             \"weak_indexes_rebuilt_at_0_75_load\":true,\
             \"source_code_excluded\":true,\"unattributed_charged_at_current_bytes\":true}}}}",
            self.captured_frames,
            self.captured_frame_slots,
            self.packed_frame_bytes,
            self.packed_dynamic_scope_upper_bytes,
            self.weak_index_entries,
            self.rebuilt_weak_index_bytes,
            WEAK_INDEX_ALLOWANCE_BYTES,
            self.rebuilt_weak_index_bytes <= WEAK_INDEX_ALLOWANCE_BYTES,
            self.unattributed_objects,
            self.unattributed_current_bytes,
            UNATTRIBUTED_GATE_BYTES,
            self.unattributed_current_bytes <= UNATTRIBUTED_GATE_BYTES,
            self.heap_lower_bytes(),
            self.heap_upper_bytes(),
            HEAP_GATE_BYTES,
            self.heap_upper_bytes() <= HEAP_GATE_BYTES,
            FRONTEND_ALLOWANCE_BYTES,
            self.named_state_upper_bytes(),
            NAMED_STATE_GATE_BYTES,
            self.named_state_upper_bytes() <= NAMED_STATE_GATE_BYTES,
        )
    }
}

impl EvalHeap {
    /// Projects the precise root-reachable graph into compact destination layouts.
    ///
    /// Hash-cons indexes are weak and therefore do not seed traversal. The
    /// method retains only integer addresses and frame identities; it never
    /// retains a runtime value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] when the ordinary weak-root traversal finds a
    /// stale root, malformed edge, invalid thunk state, or cannot grow its
    /// traversal storage.
    pub(crate) fn compact_destination_projection(
        &self,
        roots: &EvalRootSet,
    ) -> Result<CompactDestinationProjection, EvalHeapError> {
        let reachable = self.weak_reachable_addresses(roots)?;
        let mut result = CompactDestinationProjection {
            roots: roots.len() as u64,
            reachable_objects: reachable.len() as u64,
            ..CompactDestinationProjection::default()
        };
        let mut frames = HashSet::new();
        let mut contexts = HashSet::new();

        for record in &self.records {
            if record.is_retired() || !reachable.contains(&(record.ptr.as_ptr() as usize)) {
                continue;
            }
            result.unattributed_objects = result.unattributed_objects.saturating_add(1);
            result.unattributed_current_bytes = result
                .unattributed_current_bytes
                .saturating_add(record.layout.size_bytes as u64);
        }
        for object in self.flat.iter() {
            if !reachable.contains(&(object.ptr().as_ptr() as usize)) {
                continue;
            }
            let string = object.object().payload();
            let context_bytes = packed_context_bytes(string.context(), &mut contexts);
            let packed = align8(
                8_u64
                    .saturating_add(string.len() as u64)
                    .saturating_add(context_bytes),
            );
            result
                .strings_paths
                .add(object.size_bytes(), packed, packed);
            result.weak_index_entries = result.weak_index_entries.saturating_add(1);
        }
        for object in self.flat_lists.iter() {
            if !reachable.contains(&(object.ptr().as_ptr() as usize)) {
                continue;
            }
            let list = object.object().payload();
            let packed = align8(8_u64.saturating_add((list.len() as u64).saturating_mul(8)));
            let current = object
                .size_bytes()
                .saturating_add(list.capacity().saturating_mul(std::mem::size_of::<Value>()));
            result.lists.add(current, packed, packed);
            result.weak_index_entries = result.weak_index_entries.saturating_add(1);
        }
        for object in self.flat_attrs.iter() {
            if !reachable.contains(&(object.ptr().as_ptr() as usize)) {
                continue;
            }
            let attrs = &object.object().payload().attrs;
            let count = attrs.len() as u64;
            // Lower: key + value plus one object header. Upper additionally
            // preserves source positions and both observable order arrays.
            let lower = align8(8_u64.saturating_add(count.saturating_mul(12)));
            let upper = align8(8_u64.saturating_add(count.saturating_mul(32)));
            result.attrs.add(object.size_bytes(), lower, upper);
            result.weak_index_entries = result.weak_index_entries.saturating_add(1);
        }
        for object in self.flat_closures.iter() {
            if !reachable.contains(&(object.ptr().as_ptr() as usize)) {
                continue;
            }
            let current = object.size_bytes();
            match object.object().payload() {
                FlatClosurePayload::Thunk(thunk) => {
                    result.thunk_heads.add(current, 8, 8);
                    project_thunk_work(thunk, &mut result.typed_work);
                    collect_env(thunk.env(), &mut frames, &mut result);
                    collect_dynamic_scope_upper(thunk, &mut result);
                }
                FlatClosurePayload::SharedThunk(thunk) => {
                    result.thunk_heads.add(current, 8, 8);
                    project_thunk_work(thunk, &mut result.typed_work);
                    collect_env(thunk.env(), &mut frames, &mut result);
                    collect_dynamic_scope_upper(thunk, &mut result);
                }
                FlatClosurePayload::Lambda(lambda) => {
                    result.lambdas.add(current, 24, 40);
                    collect_env(Some(lambda.env()), &mut frames, &mut result);
                    let scopes = lambda
                        .with_scope_env()
                        .len()
                        .saturating_add(lambda.scoped_global_env().len());
                    result.packed_dynamic_scope_upper_bytes = result
                        .packed_dynamic_scope_upper_bytes
                        .saturating_add(packed_dynamic_scope_bytes(scopes));
                }
                FlatClosurePayload::Primop(primop) => {
                    let args = primop.args().len() as u64;
                    result.primops.add(
                        current,
                        align8(16 + args.saturating_mul(16)),
                        align8(16 + args.saturating_mul(24)),
                    );
                }
                FlatClosurePayload::Retired(_) => {}
            }
        }
        for (address, bytes) in self.typed_thunk_heads.initialized_regions() {
            if !reachable.contains(&address) {
                continue;
            }
            result.thunk_heads.add(bytes, 8, 8);
            let Some(ptr) = NonNull::new(address as *mut HeapObject) else {
                continue;
            };
            if self
                .typed_thunk_heads
                .resolve(ptr)
                .ok()
                .and_then(StableThunkHead::state)
                == Some(ThunkState::Suspended)
            {
                if let Some(work) = self.typed_thunk_work_ref(ptr)? {
                    project_thunk_work(work, &mut result.typed_work);
                    collect_env(work.env(), &mut frames, &mut result);
                    collect_dynamic_scope_upper(work, &mut result);
                }
            }
        }

        result.rebuilt_weak_index_bytes = rebuilt_weak_index_bytes(result.weak_index_entries);
        Ok(result)
    }
}

fn collect_dynamic_scope_upper(thunk: &EvalThunk, result: &mut CompactDestinationProjection) {
    let scopes = thunk
        .with_scope_env()
        .map_or(0, |env| env.len())
        .saturating_add(thunk.scoped_global_env().map_or(0, |env| env.len()));
    result.packed_dynamic_scope_upper_bytes = result
        .packed_dynamic_scope_upper_bytes
        .saturating_add(packed_dynamic_scope_bytes(scopes));
}

fn packed_dynamic_scope_bytes(scopes: usize) -> u64 {
    if scopes == 0 {
        0
    } else {
        8_u64.saturating_add((scopes as u64).saturating_mul(8))
    }
}

fn collect_env(
    env: Option<&EvalEnv>,
    frames: &mut HashSet<*const EvalFrame>,
    result: &mut CompactDestinationProjection,
) {
    let Some(env) = env else {
        return;
    };
    for frame in env.frames().iter() {
        if frames.insert(Arc::as_ptr(frame)) {
            result.captured_frames = result.captured_frames.saturating_add(1);
            result.captured_frame_slots = result
                .captured_frame_slots
                .saturating_add(frame.slot_count() as u64);
            result.packed_frame_bytes = result
                .packed_frame_bytes
                .saturating_add(8)
                .saturating_add((frame.slot_count() as u64).saturating_mul(8));
        }
    }
}

fn project_thunk_work(thunk: &EvalThunk, tally: &mut ProjectedKind) {
    if thunk.cell().state() != Ok(ThunkState::Suspended) {
        return;
    }
    let (lower, upper) = match thunk.kind() {
        EvalThunkKind::Node { .. } => (16, 24),
        EvalThunkKind::Apply { .. } | EvalThunkKind::GenListElemAtAddOne { .. } => (32, 40),
        EvalThunkKind::Apply2(_) => (48, 64),
        EvalThunkKind::Select { .. } => (16, 24),
        EvalThunkKind::BuiltinAttr { .. } => (8, 16),
        EvalThunkKind::Released => (0, 0),
    };
    if upper != 0 {
        tally.add(std::mem::size_of::<EvalThunk>(), lower, upper);
    }
}

fn packed_context_bytes(
    context: &crate::string::StringContext,
    seen: &mut HashSet<(*const crate::string::ContextElement, usize)>,
) -> u64 {
    if context.is_empty() || !seen.insert((context.elements().as_ptr(), context.len())) {
        return 0;
    }
    context.iter().fold(0_u64, |bytes, element| {
        bytes.saturating_add(align8(
            8_u64
                .saturating_add(element.path().len() as u64)
                .saturating_add(element.output().map_or(0, |output| output.len()) as u64),
        ))
    })
}

const fn align8(bytes: u64) -> u64 {
    bytes.saturating_add(7) & !7
}

const fn rebuilt_weak_index_bytes(entries: u64) -> u64 {
    // 16-byte `(hash, compact-value)` open-addressing slots at <= 0.75 load.
    entries
        .saturating_mul(4)
        .saturating_add(2)
        .saturating_div(3)
        .saturating_mul(16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_index_projection_rounds_up_to_three_quarters_load() {
        assert_eq!(rebuilt_weak_index_bytes(0), 0);
        assert_eq!(rebuilt_weak_index_bytes(1), 32);
        assert_eq!(rebuilt_weak_index_bytes(3), 64);
    }

    #[test]
    fn compact_projection_ignores_unrooted_values_and_uses_eight_byte_heads() {
        let mut heap = EvalHeap::new();
        heap.enable_typed_apply_thunk_heads();
        let rooted = heap
            .alloc_thunk(EvalThunk::new(IrId::new(7)))
            .expect("rooted thunk allocates");
        let _unrooted = heap
            .alloc_list(NixList::new(vec![Value::int(1), Value::int(2)]))
            .expect("unrooted list allocates");
        let mut roots = EvalRootSet::new();
        roots.try_push_value_stack(0, rooted).expect("root appends");

        let projection = heap
            .compact_destination_projection(&roots)
            .expect("projection succeeds");
        assert_eq!(projection.reachable_objects, 1);
        assert_eq!(projection.thunk_heads.count, 1);
        assert_eq!(projection.thunk_heads.compact_upper_bytes, 8);
        assert_eq!(projection.lists.count, 0);
        assert_eq!(projection.typed_work.count, 1);
    }

    #[test]
    fn named_state_gate_charges_unattributed_bytes_conservatively() {
        let projection = CompactDestinationProjection {
            unattributed_current_bytes: NAMED_STATE_GATE_BYTES,
            ..CompactDestinationProjection::default()
        };
        assert!(projection.named_state_upper_bytes() > NAMED_STATE_GATE_BYTES);
    }
}

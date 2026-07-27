//! Exact-source callback-free builder for the `lib/modules.nix` final-config fold.
//!
//! The builder replaces the complete `mergedOptions -> finalConfig` fold only
//! after a no-allocation preflight has proved the exact source, closure layout,
//! key order, ready context-free paths, suspended leaf values, and absence of
//! duplicate or prefix-conflicting paths. Unsupported values fall back to the
//! ordinary fold before any evaluator value is published.
//!
//! When canary reporting is enabled, Stage A also compares the complete
//! binder-selected fold graph with a checked semantic certificate covering the
//! primary fold and its captured `deepMerge`, `dedup`, and `setPath` helpers.
//! This shadow result contributes agreement and decline counters only; the
//! source-pinned exact matcher remains the sole execution admission.

use super::*;
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

const PRIMARY_MODULES_SOURCE: &[u8] = include_bytes!("../../../../../lib/modules.nix");
const PRIMARY_MERGED_OPTIONS_SLOT: u32 = 7;
const MAX_FINAL_CONFIG_PATH_DEPTH: usize = 256;

static ENABLED: OnceLock<bool> = OnceLock::new();
static REPORT_ENABLED: OnceLock<bool> = OnceLock::new();
static STAGE_B_ENABLED: OnceLock<bool> = OnceLock::new();
static FOLD_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static STRUCTURAL_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static KEY_EVENTS: AtomicU64 = AtomicU64::new(0);
static CAPTURE_MERGED_OPTIONS_THUNKS: AtomicU64 = AtomicU64::new(0);
static CAPTURE_MERGED_OPTIONS_READY: AtomicU64 = AtomicU64::new(0);
static CAPTURE_MERGED_OPTIONS_DECLINES: AtomicU64 = AtomicU64::new(0);
static CAPTURE_ATTRSETS: AtomicU64 = AtomicU64::new(0);
static CAPTURE_ENTRIES: AtomicU64 = AtomicU64::new(0);
static CAPTURE_PROJECTION_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static CAPTURE_PROJECTION_DECLINES: AtomicU64 = AtomicU64::new(0);
static PROJECTED_PATH_ELEMENTS: AtomicU64 = AtomicU64::new(0);
static PROJECTED_PATH_ELEMENT_STRINGS: AtomicU64 = AtomicU64::new(0);
static PROJECTED_FINAL_VALUE_THUNKS: AtomicU64 = AtomicU64::new(0);
static CALLBACK_FREE_EXECUTIONS: AtomicU64 = AtomicU64::new(0);
static FIRST_PROJECTION_DIAGNOSTIC: AtomicU64 = AtomicU64::new(0);
static STAGE_A_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static STAGE_A_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static STAGE_A_EXACT_AGREEMENTS: AtomicU64 = AtomicU64::new(0);
static STAGE_A_EXACT_ONLY: AtomicU64 = AtomicU64::new(0);
static STAGE_A_GENERIC_ONLY: AtomicU64 = AtomicU64::new(0);
static STAGE_A_BOTH_DECLINE: AtomicU64 = AtomicU64::new(0);
static STAGE_A_REFERENCE_ERRORS: AtomicU64 = AtomicU64::new(0);
static STAGE_A_CONTEXT_ERRORS: AtomicU64 = AtomicU64::new(0);
static STAGE_A_CERTIFICATE_MISMATCHES: AtomicU64 = AtomicU64::new(0);
static STAGE_A_REFERENCE: OnceLock<StageATransducerCertificate> = OnceLock::new();
static STAGE_B_REFERENCE: OnceLock<Option<StageATransducerCertificate>> = OnceLock::new();
#[cfg(feature = "nonmoving_reclaim_probe")]
static NONMOVING_RECLAIM_EXECUTIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "nonmoving_reclaim_probe")]
static NONMOVING_RECLAIM_SELECTED_EXECUTION: OnceLock<Option<usize>> = OnceLock::new();
#[cfg(feature = "nonmoving_reclaim_probe")]
static NONMOVING_RECLAIM_SAMPLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "evacuation_plan_probe")]
static EVACUATION_PLAN_EXECUTIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "evacuation_plan_probe")]
static EVACUATION_PLAN_SELECTED_EXECUTIONS: OnceLock<Option<EvacuationProbeSchedule>> =
    OnceLock::new();
#[cfg(feature = "evacuation_plan_probe")]
static EVACUATION_PLAN_SAMPLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "mesh_projection_probe")]
static MESH_PROJECTION_EXECUTIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "mesh_projection_probe")]
static MESH_PROJECTION_SELECTED_EXECUTION: OnceLock<Option<usize>> = OnceLock::new();
#[cfg(feature = "mesh_projection_probe")]
static MESH_PROJECTION_SAMPLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "evacuation_plan_probe")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct EvacuationProbeSchedule {
    executions: Vec<usize>,
}

#[cfg(feature = "evacuation_plan_probe")]
impl EvacuationProbeSchedule {
    /// Parses a single execution or a comma-separated cadence.
    fn parse(value: &str) -> Option<Self> {
        let mut executions = value
            .split(',')
            .map(str::trim)
            .map(str::parse::<usize>)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        if executions.is_empty() || executions.contains(&0) {
            return None;
        }
        executions.sort_unstable();
        executions.dedup();
        Some(Self { executions })
    }

    /// Returns whether `execution` is one of the selected quiescent points.
    fn contains(&self, execution: usize) -> bool {
        self.executions.binary_search(&execution).is_ok()
    }

    /// Returns whether this schedule contains repeated collection points.
    fn is_cadence(&self) -> bool {
        self.executions.len() > 1
    }
}

/// Captured coordinate proved by the complete source-pinned fold match.
#[derive(Clone, Copy, Debug)]
pub(super) struct FinalConfigTriePlan {
    capture_depth: usize,
    capture_slot: u32,
    entry_record_thunk_site: IrId,
    entry_record_body: IrId,
    entry_record_uses_flat_capture: bool,
    path_owner_depth: usize,
    path_owner_slot: u32,
    final_value_depth: usize,
    final_value_slot: u32,
    path_symbol: Symbol,
    decl_thunk_site: IrId,
    decl_body: IrId,
    decl_key_depth: usize,
    decl_key_slot: u32,
    option_map_depth: usize,
    option_map_slot: u32,
    option_map_alias_thunk_site: IrId,
    option_map_alias_body: IrId,
    option_map_alias_decl_depth: usize,
    option_map_alias_decl_slot: u32,
    deep_merge_construction: FinalConfigAttrConstruction,
    set_path_construction: FinalConfigAttrConstruction,
}

/// One exact attrset allocation site and its observable binding provenance.
#[derive(Clone, Copy, Debug)]
struct FinalConfigAttrConstruction {
    site: IrId,
    shape: u32,
    binding_position: Option<Span>,
}

/// Checked semantic reference for the complete fold and its captured helpers.
#[derive(Debug, PartialEq, Eq)]
struct StageATransducerCertificate {
    fold: Box<[u8]>,
    deep_merge: Box<[u8]>,
    dedup: Box<[u8]>,
    set_path: Box<[u8]>,
}

impl StageATransducerCertificate {
    fn total_bytes(&self) -> usize {
        self.fold
            .len()
            .saturating_add(self.deep_merge.len())
            .saturating_add(self.dedup.len())
            .saturating_add(self.set_path.len())
    }
}

/// One unpublished, prefix-free final-config trie node.
#[derive(Debug, Default)]
struct FinalConfigTrieNode {
    contribution_count: usize,
    last_key: Option<Symbol>,
    last_key_existed: bool,
    children: std::collections::BTreeMap<Symbol, FinalConfigTrieEdge>,
}

/// One edge in an unpublished final-config trie.
#[derive(Debug)]
enum FinalConfigTrieEdge {
    Node(Box<FinalConfigTrieNode>),
    Leaf(Value),
}

/// A path relationship that requires the ordinary `deepMerge` evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FinalConfigTrieDecline {
    EmptyPath,
    DuplicatePath,
    ProperPrefix,
    ExcessiveDepth,
}

/// The source construction whose metadata one direct node must reproduce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FinalConfigConstructionKind {
    DeepMerge,
    SetPath,
}

impl FinalConfigTrieNode {
    /// Appends every unpublished leaf value in deterministic trie order.
    fn append_leaf_values(&self, values: &mut Vec<Value>) -> bool {
        for edge in self.children.values() {
            match edge {
                FinalConfigTrieEdge::Node(child) => {
                    if !child.append_leaf_values(values) {
                        return false;
                    }
                }
                FinalConfigTrieEdge::Leaf(value) => {
                    if values.try_reserve_exact(1).is_err() {
                        return false;
                    }
                    values.push(*value);
                }
            }
        }
        true
    }

    /// Inserts one path in original fold order without publishing a value.
    fn insert(
        &mut self,
        path: &[Symbol],
        final_value: Value,
    ) -> Result<(), FinalConfigTrieDecline> {
        if path.is_empty() {
            return Err(FinalConfigTrieDecline::EmptyPath);
        }
        if path.len() > MAX_FINAL_CONFIG_PATH_DEPTH {
            return Err(FinalConfigTrieDecline::ExcessiveDepth);
        }
        self.insert_nonempty(path, final_value)
    }

    /// Inserts one known-nonempty suffix.
    fn insert_nonempty(
        &mut self,
        path: &[Symbol],
        final_value: Value,
    ) -> Result<(), FinalConfigTrieDecline> {
        let key = path[0];
        let existed = self.children.contains_key(&key);
        self.contribution_count = self.contribution_count.saturating_add(1);
        self.last_key = Some(key);
        self.last_key_existed = existed;

        match (self.children.entry(key), &path[1..]) {
            (std::collections::btree_map::Entry::Vacant(entry), []) => {
                entry.insert(FinalConfigTrieEdge::Leaf(final_value));
                Ok(())
            }
            (std::collections::btree_map::Entry::Vacant(entry), suffix) => {
                let mut child = FinalConfigTrieNode::default();
                child.insert_nonempty(suffix, final_value)?;
                entry.insert(FinalConfigTrieEdge::Node(Box::new(child)));
                Ok(())
            }
            (std::collections::btree_map::Entry::Occupied(entry), []) => match entry.get() {
                FinalConfigTrieEdge::Leaf(_) => Err(FinalConfigTrieDecline::DuplicatePath),
                FinalConfigTrieEdge::Node(_) => Err(FinalConfigTrieDecline::ProperPrefix),
            },
            (std::collections::btree_map::Entry::Occupied(mut entry), suffix) => {
                match entry.get_mut() {
                    FinalConfigTrieEdge::Node(child) => child.insert_nonempty(suffix, final_value),
                    FinalConfigTrieEdge::Leaf(_) => Err(FinalConfigTrieDecline::ProperPrefix),
                }
            }
        }
    }

    /// Returns the final `listToAttrs` source order for this node.
    fn source_order_keys(&self, symbols: &SymbolTable) -> Option<Vec<Symbol>> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(self.children.len()).ok()?;
        keys.extend(self.children.keys().copied());
        keys.sort_unstable_by(|left, right| {
            symbols
                .resolve(*left)
                .cmp(&symbols.resolve(*right))
                .then_with(|| left.cmp(right))
        });
        if !self.last_key_existed {
            let last_key = self.last_key?;
            let index = keys.iter().position(|key| *key == last_key)?;
            keys[index..].rotate_left(1);
        }
        Some(keys)
    }

    /// Selects the original construction responsible for this node's entries.
    const fn construction_kind(&self, is_root: bool) -> FinalConfigConstructionKind {
        if is_root || self.contribution_count > 1 {
            FinalConfigConstructionKind::DeepMerge
        } else {
            FinalConfigConstructionKind::SetPath
        }
    }
}

fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var_os("AOS_NIX_FINAL_CONFIG_TRIE_CANARY").is_some_and(|value| value == "1")
    })
}

fn report_enabled() -> bool {
    *REPORT_ENABLED.get_or_init(|| {
        std::env::var_os("AOS_NIX_FINAL_CONFIG_TRIE_CANARY_REPORT")
            .is_some_and(|value| value == "1")
    })
}

fn stage_b_enabled() -> bool {
    *STAGE_B_ENABLED.get_or_init(|| {
        std::env::var_os("AOS_NIX_FINAL_CONFIG_TRIE_STAGE_B").is_some_and(|value| value == "1")
    })
}

#[cfg(feature = "evacuation_plan_probe")]
fn hash_map_storage_lower_bytes<K, V, S>(map: &HashMap<K, V, S>) -> usize {
    map.capacity().saturating_mul(
        std::mem::size_of::<K>()
            .saturating_add(std::mem::size_of::<V>())
            .saturating_add(1),
    )
}

impl TreeWalk {
    /// Executes one exact final-config fold without interpreter callbacks.
    pub(super) fn try_eval_final_config_trie_fold(
        &mut self,
        fold: IrId,
        operator: Value,
        keys: &[Value],
    ) -> Result<Option<Value>, TreeWalkError> {
        if !enabled() || !self.final_config_trie_runtime_enabled() {
            return Ok(None);
        }
        if report_enabled() {
            FOLD_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        }
        let key = EvalNodeRef::new(self.current_module, fold);
        let plan = if let Some(plan) = self.final_config_trie_plans.get(&key) {
            *plan
        } else {
            let plan = self.match_final_config_trie_fold(fold);
            self.final_config_trie_plans.insert(key, plan);
            plan
        };
        let Some(plan) = plan else {
            return Ok(None);
        };
        let Ok(lambda) = self.heap.get_lambda(operator) else {
            return Ok(None);
        };
        if !self.final_config_fold_operator_matches(fold, lambda) {
            return Ok(None);
        }
        let Some(mut merged_options) =
            self.captured_env_value_at_depth(lambda.env(), plan.capture_depth, plan.capture_slot)
        else {
            return Ok(None);
        };
        if report_enabled() {
            STRUCTURAL_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
            KEY_EVENTS.fetch_add(keys.len() as u64, Ordering::Relaxed);
        }
        if merged_options.tag() == ValueTag::Thunk {
            if report_enabled() {
                CAPTURE_MERGED_OPTIONS_THUNKS.fetch_add(1, Ordering::Relaxed);
            }
            let Some(ready) = self.peek_final_config_forced_value(merged_options) else {
                if report_enabled() {
                    CAPTURE_MERGED_OPTIONS_DECLINES.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(None);
            };
            merged_options = ready;
            if report_enabled() {
                CAPTURE_MERGED_OPTIONS_READY.fetch_add(1, Ordering::Relaxed);
            }
        }
        if merged_options.tag() != ValueTag::Attrs {
            return Ok(None);
        }
        let Ok(merged_attrs) = self.heap.get_attrs(merged_options) else {
            return Ok(None);
        };
        if report_enabled() {
            CAPTURE_ATTRSETS.fetch_add(1, Ordering::Relaxed);
            CAPTURE_ENTRIES.fetch_add(merged_attrs.len() as u64, Ordering::Relaxed);
        }
        let mut entries = Vec::new();
        if entries.try_reserve_exact(merged_attrs.len()).is_err() {
            return Ok(None);
        }
        entries.extend(merged_attrs.iter_lexicographic().copied());
        if entries.len() != keys.len() || entries.is_empty() {
            return Ok(None);
        }

        // Phase one: validate and build an unpublished trie. This performs no
        // evaluator allocation, force, apply, select, or thunk publication.
        let mut trie = FinalConfigTrieNode::default();
        for (key_value, entry) in keys.iter().copied().zip(entries) {
            if !self.final_config_fold_key_matches_entry(key_value, entry.key) {
                return Ok(None);
            }
            let Some((path, final_value)) = self.project_final_config_entry(plan, entry) else {
                if report_enabled() {
                    CAPTURE_PROJECTION_DECLINES.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(None);
            };
            if trie.insert(&path, final_value).is_err() {
                return Ok(None);
            }
            if report_enabled() {
                CAPTURE_PROJECTION_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
                PROJECTED_PATH_ELEMENTS.fetch_add(path.len() as u64, Ordering::Relaxed);
                PROJECTED_PATH_ELEMENT_STRINGS.fetch_add(path.len() as u64, Ordering::Relaxed);
                PROJECTED_FINAL_VALUE_THUNKS.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Phase two: every decline door is closed. Allocate child attrsets
        // bottom-up and return the sole published root.
        #[cfg(feature = "collection_poll_probe")]
        let value = if self.native_continuation_shadow_enabled() {
            let mut roots = Vec::new();
            if roots.try_reserve_exact(2).is_ok() {
                roots.push(operator);
                roots.push(merged_options);
            }
            if roots.len() == 2 && trie.append_leaf_values(&mut roots) {
                self.with_nonmoving_native_continuation(
                    super::native_continuation_shadow::NativeContinuationKind::CanaryPublish,
                    fold,
                    &roots,
                    None,
                    |eval| eval.allocate_final_config_trie_node(&trie, plan, true),
                )?
            } else {
                self.allocate_final_config_trie_node(&trie, plan, true)?
            }
        } else {
            self.allocate_final_config_trie_node(&trie, plan, true)?
        };
        #[cfg(not(feature = "collection_poll_probe"))]
        let value = self.allocate_final_config_trie_node(&trie, plan, true)?;
        if report_enabled() {
            CALLBACK_FREE_EXECUTIONS.fetch_add(1, Ordering::Relaxed);
        }
        #[cfg(feature = "collection_poll_probe")]
        if self.native_continuation_shadow_enabled() {
            let span = self.node(fold)?.span;
            let mut roots = [value];
            return self.with_terminal_writeback_native_continuation(
                super::native_continuation_shadow::NativeContinuationKind::CanaryCompletion,
                fold,
                span,
                &mut roots,
                |eval, slots| {
                    eval.finish_final_config_trie_completion_from_transient_slot(
                        fold,
                        span,
                        slots.start,
                    )
                },
            );
        }
        self.finish_final_config_trie_completion(value)
    }

    /// Runs completion probes and reloads the result from its writable root.
    ///
    /// The reload is deliberately after every completion hook. A moving
    /// collection may eventually be inserted at the end of those hooks without
    /// returning the pre-move value copied into this native frame.
    fn finish_final_config_trie_completion_from_transient_slot(
        &mut self,
        id: IrId,
        span: Span,
        slot: usize,
    ) -> Result<Option<Value>, TreeWalkError> {
        let value = self
            .current_transient_value_stack_root(slot)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        self.note_final_config_trie_completion(value);
        let relocated = self
            .current_transient_value_stack_root(slot)
            .ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::SafepointRootStackLengthOverflow { id },
                    span,
                )
            })?;
        Ok(Some(relocated))
    }

    fn finish_final_config_trie_completion(
        &mut self,
        value: Value,
    ) -> Result<Option<Value>, TreeWalkError> {
        self.note_final_config_trie_completion(value);
        // This path has no explicit completion root because collection-poll
        // support is absent. The portal remains inert in that configuration.
        Ok(Some(value))
    }

    /// Runs report-only and nonmoving hooks at one callback-free completion.
    fn note_final_config_trie_completion(&mut self, value: Value) {
        #[cfg(feature = "nested_nonmoving_retirement_probe")]
        self.note_rotating_rollover_final_config_completion(value);
        #[cfg(feature = "young_increment_projection_probe")]
        self.note_young_increment_final_config_completion(value);
        #[cfg(feature = "root_continuation_probe")]
        self.note_root_continuation_final_config_completion();
        #[cfg(feature = "collection_poll_probe")]
        self.note_whole_demand_final_config_completion();
        #[cfg(feature = "collection_poll_probe")]
        self.note_nested_nonmoving_final_config_completion(value);
        #[cfg(feature = "nested_nonmoving_retirement_probe")]
        self.note_nested_nonmoving_retirement_completion(value);
        #[cfg(feature = "collection_poll_probe")]
        self.note_restart_to_root_final_config_completion();
        #[cfg(feature = "lifetime_cohort_probe")]
        self.note_lifetime_cohort_final_config(value);
        #[cfg(feature = "nonmoving_reclaim_probe")]
        self.emit_final_config_nonmoving_reclaim_projection(value);
        #[cfg(feature = "evacuation_plan_probe")]
        self.emit_final_config_evacuation_plan(value);
        #[cfg(feature = "mesh_projection_probe")]
        self.emit_final_config_mesh_projection(value);
        #[cfg(feature = "immutable_cohort_projection_probe")]
        self.note_immutable_cohort_final_config_completion();
    }

    /// Emits one read-only virtual-page meshing projection.
    #[cfg(feature = "mesh_projection_probe")]
    fn emit_final_config_mesh_projection(&self, value: Value) {
        let execution_count = MESH_PROJECTION_EXECUTIONS
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let selected_execution = MESH_PROJECTION_SELECTED_EXECUTION.get_or_init(|| {
            std::env::var("AOS_NIX_MESH_PROJECTION_FINAL_CONFIG")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
        });
        if *selected_execution != Some(execution_count)
            || MESH_PROJECTION_SAMPLED
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }

        let modules = self.modules.len();
        let result = self
            .mutator_root_set()
            .and_then(|mut roots| {
                roots
                    .try_push_value_stack(0, value)
                    .map_err(TreeWalkSafepointRootError::RootSet)?;
                Ok(roots)
            })
            .map_err(|error| error.to_string())
            .and_then(|roots| {
                self.heap
                    .mesh_projection(&roots)
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(projection) => eprintln!(
                "aos_nix_mesh_projection_final_config \
                 execution_count={execution_count} modules={modules} {projection}"
            ),
            Err(error) => eprintln!(
                "aos_nix_mesh_projection_final_config_error \
                 {{\"execution_count\":{execution_count},\"modules\":{modules},\
                 \"error\":{error:?}}}"
            ),
        }
    }

    /// Emits persistent evaluator-cache storage at an evacuation checkpoint.
    #[cfg(feature = "evacuation_plan_probe")]
    fn emit_final_config_cache_storage_census(&self, execution_count: usize) {
        let flat_pic_entries = self
            .flat_select_caches
            .values()
            .map(|cache| cache.state().entry_count())
            .sum::<usize>();
        let shaped_pic_entries = self
            .shaped_select_caches
            .values()
            .map(|cache| cache.state().entry_count())
            .sum::<usize>();
        let record_pic_entries = self
            .record_select_caches
            .values()
            .map(|cache| cache.state().entry_count())
            .sum::<usize>();
        let primop = self.primop_builtin_cache.storage_counts();
        let formal = self.formal_set_layout_cache.storage_counts();
        eprintln!(
            "aos_nix_cache_storage_final_config \
             {{\"execution_count\":{execution_count},\
             \"flat\":{{\"len\":{},\"capacity\":{},\"pic_entries\":{},\
             \"map_lower_bytes\":{}}},\
             \"shaped\":{{\"len\":{},\"capacity\":{},\"pic_entries\":{},\
             \"map_lower_bytes\":{}}},\
             \"record\":{{\"len\":{},\"capacity\":{},\"pic_entries\":{},\
             \"map_lower_bytes\":{}}},\
             \"hamt\":{{\"len\":{},\"capacity\":{},\"map_lower_bytes\":{}}},\
             \"static_shapes\":{{\"len\":{},\"capacity\":{},\
             \"map_lower_bytes\":{}}},\
             \"primop\":{{\"module_len\":{},\"module_capacity\":{},\
             \"slot_len\":{},\"slot_capacity\":{},\"populated\":{},\
             \"structural_bytes\":{}}},\
             \"formal\":{{\"module_len\":{},\"module_capacity\":{},\
             \"slot_len\":{},\"slot_capacity\":{},\"layouts\":{},\
             \"formal_entries\":{},\"structural_lower_bytes\":{}}}}}",
            self.flat_select_caches.len(),
            self.flat_select_caches.capacity(),
            flat_pic_entries,
            hash_map_storage_lower_bytes(&self.flat_select_caches),
            self.shaped_select_caches.len(),
            self.shaped_select_caches.capacity(),
            shaped_pic_entries,
            hash_map_storage_lower_bytes(&self.shaped_select_caches),
            self.record_select_caches.len(),
            self.record_select_caches.capacity(),
            record_pic_entries,
            hash_map_storage_lower_bytes(&self.record_select_caches),
            self.hamt_select_caches.len(),
            self.hamt_select_caches.capacity(),
            hash_map_storage_lower_bytes(&self.hamt_select_caches),
            self.static_literal_shapes.len(),
            self.static_literal_shapes.capacity(),
            hash_map_storage_lower_bytes(&self.static_literal_shapes),
            primop.0,
            primop.1,
            primop.2,
            primop.3,
            primop.4,
            primop
                .1
                .saturating_mul(std::mem::size_of::<
                    Vec<Option<primop_builtin_cache::CachedPrimop>>,
                >())
                .saturating_add(primop.3.saturating_mul(std::mem::size_of::<
                    Option<primop_builtin_cache::CachedPrimop>,
                >())),
            formal.0,
            formal.1,
            formal.2,
            formal.3,
            formal.4,
            formal.5,
            formal
                .1
                .saturating_mul(std::mem::size_of::<
                    Vec<Option<Arc<formal_set_layout_cache::FormalSetLayout>>>,
                >())
                .saturating_add(formal.3.saturating_mul(std::mem::size_of::<
                    Option<Arc<formal_set_layout_cache::FormalSetLayout>>,
                >()),)
                .saturating_add(formal.4.saturating_mul(std::mem::size_of::<
                    formal_set_layout_cache::FormalSetLayout,
                >()),)
                .saturating_add(
                    formal
                        .5
                        .saturating_mul(std::mem::size_of::<formal_set_layout_cache::FormalSlot>()),
                ),
        );
    }

    /// Emits evacuation work after a selected direct execution.
    ///
    /// `AOS_NIX_EVACUATION_PLAN_FINAL_CONFIG` accepts either one execution or
    /// a comma-separated cadence. At every selected quiescent point the probe
    /// plans. `AOS_NIX_EVACUATION_WRITE_FINAL_CONFIG=1` additionally builds and
    /// validates the private correctness-oracle destination without publishing
    /// it. The probe can then optionally run the validate-then-retire worker
    /// sweep and dead-page advice. Roots are rebuilt for each mutating sweep so
    /// repeated collections cannot retain a stale snapshot from an earlier
    /// plan.
    #[cfg(feature = "evacuation_plan_probe")]
    fn emit_final_config_evacuation_plan(&mut self, value: Value) {
        let execution_count = EVACUATION_PLAN_EXECUTIONS
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let selected_executions = EVACUATION_PLAN_SELECTED_EXECUTIONS.get_or_init(|| {
            std::env::var("AOS_NIX_EVACUATION_PLAN_FINAL_CONFIG")
                .ok()
                .and_then(|value| EvacuationProbeSchedule::parse(&value))
        });
        let Some(selected_executions) = selected_executions else {
            return;
        };
        if !selected_executions.contains(execution_count) {
            return;
        }
        if !selected_executions.is_cadence()
            && EVACUATION_PLAN_SAMPLED
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }

        let modules = self.modules.len();
        self.emit_final_config_cache_storage_census(execution_count);
        let result = self
            .mutator_root_set()
            .and_then(|mut roots| {
                roots
                    .try_push_value_stack(0, value)
                    .map_err(TreeWalkSafepointRootError::RootSet)?;
                Ok(roots)
            })
            .map_err(|error| error.to_string())
            .and_then(|roots| {
                self.heap
                    .evacuation_plan(&roots)
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(plan) => {
                eprintln!(
                    "aos_nix_evacuation_plan_final_config \
                     execution_count={execution_count} modules={modules} {plan}"
                );
                if std::env::var("AOS_NIX_EVACUATION_WRITE_FINAL_CONFIG")
                    .is_ok_and(|value| value == "1")
                {
                    match self.heap.write_supported_evacuation_destination(&plan) {
                        Ok(destination) => eprintln!(
                            "aos_nix_evacuation_destination_final_config \
                             {{\"execution_count\":{execution_count},\"modules\":{modules},\
                             \"forwarding\":{}}}",
                            destination.forwarding().len()
                        ),
                        Err(error) => eprintln!(
                            "aos_nix_evacuation_destination_final_config_error \
                             {{\"execution_count\":{execution_count},\"modules\":{modules},\
                             \"error\":{error:?}}}"
                        ),
                    }
                }
            }
            Err(error) => eprintln!(
                "aos_nix_evacuation_plan_final_config_error \
                 {{\"execution_count\":{execution_count},\"modules\":{modules},\
                \"error\":{error:?}}}"
            ),
        }

        if !std::env::var("AOS_NIX_EVACUATION_SWEEP_FINAL_CONFIG").is_ok_and(|value| value == "1") {
            return;
        }
        let sweep = self
            .mutator_root_set()
            .and_then(|mut roots| {
                roots
                    .try_push_value_stack(0, value)
                    .map_err(TreeWalkSafepointRootError::RootSet)?;
                Ok(roots)
            })
            .map_err(|error| error.to_string())
            .and_then(|roots| {
                self.heap
                    .sweep_unreachable_worker_records(&roots)
                    .map_err(|error| error.to_string())
            });
        match sweep {
            Ok(report) => {
                eprintln!(
                    "aos_nix_evacuation_sweep_final_config \
                     execution_count={execution_count} modules={modules} {report:?}"
                );
                if std::env::var("AOS_NIX_EVACUATION_ADVISE_DEAD_PAGES")
                    .is_ok_and(|value| value == "1")
                {
                    match self.heap.advise_tombstoned_reservation_pages() {
                        Ok(advice) => eprintln!(
                            "aos_nix_evacuation_dead_page_advice_final_config \
                             execution_count={execution_count} modules={modules} {advice:?}"
                        ),
                        Err(error) => eprintln!(
                            "aos_nix_evacuation_dead_page_advice_final_config_error \
                             {{\"execution_count\":{execution_count},\"modules\":{modules},\
                             \"error\":{error:?}}}"
                        ),
                    }
                }
            }
            Err(error) => eprintln!(
                "aos_nix_evacuation_sweep_final_config_error \
                 {{\"execution_count\":{execution_count},\"modules\":{modules},\
                 \"error\":{error:?}}}"
            ),
        }
    }

    /// Emits one read-only reclamation projection after a selected direct execution.
    #[cfg(feature = "nonmoving_reclaim_probe")]
    fn emit_final_config_nonmoving_reclaim_projection(&self, value: Value) {
        let execution_count = NONMOVING_RECLAIM_EXECUTIONS
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let selected_execution = NONMOVING_RECLAIM_SELECTED_EXECUTION.get_or_init(|| {
            std::env::var("AOS_NIX_NONMOVING_RECLAIM_FINAL_CONFIG")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
        });
        if *selected_execution != Some(execution_count)
            || NONMOVING_RECLAIM_SAMPLED
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }

        let modules = self.modules.len();
        let rss = ProcessResidentMemorySample::current()
            .ok()
            .flatten()
            .map_or(0, ProcessResidentMemorySample::resident_bytes);
        let result = self
            .mutator_root_set()
            .and_then(|mut roots| {
                roots
                    .try_push_value_stack(0, value)
                    .map_err(TreeWalkSafepointRootError::RootSet)?;
                Ok(roots)
            })
            .map_err(|error| error.to_string())
            .and_then(|roots| {
                self.heap
                    .nonmoving_reclaim_projection(&roots, rss as u64, modules, true)
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(projection) => eprintln!(
                "aos_nix_nonmoving_reclaim_final_config \
                 execution_count={execution_count} modules={modules} {projection}"
            ),
            Err(error) => eprintln!(
                "aos_nix_nonmoving_reclaim_final_config_error \
                 {{\"execution_count\":{execution_count},\"modules\":{modules},\
                 \"error\":{error:?}}}"
            ),
        }
    }

    /// Checks that one `attrNames` element names the paired lexicographic entry.
    fn final_config_fold_key_matches_entry(&self, key: Value, expected: Symbol) -> bool {
        let Ok(key) = self.heap.get_string(key) else {
            return false;
        };
        key.context().is_empty() && self.symbols.resolve(expected) == Some(key.bytes())
    }

    /// Projects one exact entry into ready symbols and a suspended leaf thunk.
    fn project_final_config_entry(
        &self,
        plan: FinalConfigTriePlan,
        entry: AttrEntry,
    ) -> Option<(Vec<Symbol>, Value)> {
        let Ok(thunk) = self.heap.get_thunk(entry.value) else {
            self.report_final_config_projection_diagnostic("entry-not-thunk");
            return None;
        };
        let EvalThunkKind::Node { body, env } = thunk.kind() else {
            self.report_final_config_projection_diagnostic("entry-not-node-thunk");
            return None;
        };
        if body.module() != self.current_module {
            self.report_final_config_projection_diagnostic("entry-module-mismatch");
            return None;
        }
        if body.id() != plan.entry_record_body {
            self.report_final_config_projection_diagnostic("entry-body-mismatch");
            return None;
        }
        match (plan.entry_record_uses_flat_capture, env.flat_base()) {
            (true, Some(flat_base))
                if flat_base.allocation_site()
                    == EvalNodeRef::new(self.current_module, plan.entry_record_thunk_site) => {}
            (false, None) => {}
            (true, None) => {
                self.report_final_config_projection_diagnostic("entry-env-not-flat");
                return None;
            }
            (false, Some(_)) => {
                self.report_final_config_projection_diagnostic("entry-env-unexpectedly-flat");
                return None;
            }
            (true, Some(_)) => {
                self.report_final_config_projection_diagnostic("entry-site-mismatch");
                return None;
            }
        }
        let path_owner =
            self.captured_env_value_at_depth(env, plan.path_owner_depth, plan.path_owner_slot)?;
        let final_value =
            self.captured_env_value_at_depth(env, plan.final_value_depth, plan.final_value_slot)?;
        let final_thunk = self.heap.get_thunk(final_value).ok()?;
        if final_thunk.cell().state().ok()? != ThunkState::Suspended {
            return None;
        }
        let path = self.project_final_config_path_owner(plan, entry.key, path_owner)?;
        Some((path, final_value))
    }

    /// Emits the first report-only reason an executable projection declined.
    fn report_final_config_projection_diagnostic(&self, reason: &'static str) {
        if report_enabled()
            && FIRST_PROJECTION_DIAGNOSTIC
                .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            eprintln!("aos_nix_final_config_trie_projection_decline reason={reason}");
        }
    }

    /// Projects the exact declaration path without entering the force protocol.
    fn project_final_config_path_owner(
        &self,
        plan: FinalConfigTriePlan,
        entry_key: Symbol,
        path_owner: Value,
    ) -> Option<Vec<Symbol>> {
        let path = match path_owner.tag() {
            ValueTag::Attrs => self
                .heap
                .get_attrs(path_owner)
                .ok()?
                .get(plan.path_symbol)?,
            ValueTag::Thunk => {
                let owner = self.heap.get_thunk(path_owner).ok()?;
                let EvalThunkKind::Node {
                    body: owner_body,
                    env: owner_env,
                } = owner.kind()
                else {
                    return None;
                };
                if owner_body.module() != self.current_module
                    || owner_body.id() != plan.decl_body
                    || owner_env.flat_base()?.allocation_site()
                        != EvalNodeRef::new(self.current_module, plan.decl_thunk_site)
                {
                    return None;
                }
                let key = self.captured_env_value_at_depth(
                    owner_env,
                    plan.decl_key_depth,
                    plan.decl_key_slot,
                )?;
                let key = self.heap.get_string(key).ok()?;
                if !key.context().is_empty() || self.symbols.resolve(entry_key) != Some(key.bytes())
                {
                    return None;
                }
                let option_map = self.captured_env_value_at_depth(
                    owner_env,
                    plan.option_map_depth,
                    plan.option_map_slot,
                )?;
                let option_map = self.peek_final_config_forced_value(option_map)?;
                let decl = self.heap.get_attrs(option_map).ok()?.get(entry_key)?;
                let decl = self.project_final_config_decl_alias(plan, decl)?;
                let decl = self.peek_final_config_forced_value(decl)?;
                self.heap.get_attrs(decl).ok()?.get(plan.path_symbol)?
            }
            _ => return None,
        };
        let path = self.peek_final_config_forced_value(path)?;
        let path = self.heap.get_list(path).ok()?;
        self.project_ready_final_config_path(path)
    }

    /// Projects the exact option-map alias thunk or its already-ready value.
    fn project_final_config_decl_alias(
        &self,
        plan: FinalConfigTriePlan,
        decl: Value,
    ) -> Option<Value> {
        let thunk = self.heap.get_thunk(decl).ok()?;
        let EvalThunkKind::Node { body, env } = thunk.kind() else {
            return None;
        };
        self.project_final_config_alias_capture(thunk, *body, env, plan)
    }

    /// Converts one already-ready context-free path into existing symbols.
    fn project_ready_final_config_path(&self, path: &NixList) -> Option<Vec<Symbol>> {
        if path.is_empty() || path.len() > MAX_FINAL_CONFIG_PATH_DEPTH {
            return None;
        }
        let mut projected = Vec::new();
        projected.try_reserve_exact(path.len()).ok()?;
        for element in path.as_slice() {
            let element = self.peek_final_config_forced_value(*element)?;
            let element = self.heap.get_string(element).ok()?;
            if !element.context().is_empty() {
                return None;
            }
            projected.push(self.symbols.lookup(element.bytes())?);
        }
        Some(projected)
    }

    /// Allocates one admitted trie node after all decline checks have passed.
    fn allocate_final_config_trie_node(
        &mut self,
        node: &FinalConfigTrieNode,
        plan: FinalConfigTriePlan,
        is_root: bool,
    ) -> Result<Value, TreeWalkError> {
        let kind = node.construction_kind(is_root);
        let construction = match kind {
            FinalConfigConstructionKind::DeepMerge => plan.deep_merge_construction,
            FinalConfigConstructionKind::SetPath => plan.set_path_construction,
        };
        let keys = node.source_order_keys(&self.symbols).ok_or_else(|| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id: construction.site,
                    source: AttrError::AllocationFailed {
                        entries: node.children.len(),
                    },
                },
                self.node(construction.site)
                    .map_or(Span::new(0, 0), |site| site.span),
            )
        })?;
        let span = self.node(construction.site)?.span;
        let mut entries = Vec::new();
        entries.try_reserve_exact(keys.len()).map_err(|_| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id: construction.site,
                    source: AttrError::AllocationFailed {
                        entries: keys.len(),
                    },
                },
                span,
            )
        })?;
        for key in keys {
            let edge = node.children.get(&key).ok_or_else(|| {
                TreeWalkError::new(
                    TreeWalkErrorKind::MissingAttribute {
                        id: construction.site,
                        symbol: key,
                    },
                    span,
                )
            })?;
            let value = match edge {
                FinalConfigTrieEdge::Node(child) => {
                    self.allocate_final_config_trie_node(child, plan, false)?
                }
                FinalConfigTrieEdge::Leaf(value) => *value,
            };
            entries.push(match construction.binding_position {
                Some(position) => AttrEntry::with_position(
                    key,
                    value,
                    AttrPosition::new(self.current_module.as_u32(), position),
                ),
                None => AttrEntry::new(key, value),
            });
        }
        let attrs = FlatAttrs::new(entries, &self.symbols).map_err(|source| {
            TreeWalkError::new(
                TreeWalkErrorKind::Attr {
                    id: construction.site,
                    source,
                },
                span,
            )
        })?;
        let len = attrs.len();
        self.alloc_flat_attrs_with_repr_telemetry(
            construction.site,
            span,
            construction.shape,
            attrs,
            AttrSetConstruction::Dynamic { len },
        )
    }

    /// Emits the process-wide executable-fold census.
    pub(super) fn emit_final_config_trie_canary_report(&self) {
        if !report_enabled() {
            return;
        }
        eprintln!(
            "aos_nix_final_config_trie_canary \
             {{\"fold_attempts\":{},\"structural_admissions\":{},\
             \"key_events\":{},\"capture_merged_options_thunks\":{},\
             \"capture_merged_options_ready\":{},\
             \"capture_merged_options_declines\":{},\
             \"capture_attrsets\":{},\"capture_entries\":{},\
             \"capture_projection_admissions\":{},\
             \"capture_projection_declines\":{},\
             \"projected_path_elements\":{},\
             \"projected_path_element_strings\":{},\
             \"projected_final_value_thunks\":{},\
             \"callback_free_executions\":{},\
             \"stage_a_attempts\":{},\"stage_a_admissions\":{},\
             \"stage_a_exact_agreements\":{},\"stage_a_exact_only\":{},\
             \"stage_a_generic_only\":{},\"stage_a_both_decline\":{},\
             \"stage_a_reference_errors\":{},\"stage_a_context_errors\":{},\
             \"stage_a_certificate_mismatches\":{},\
             \"stage_a_reference_bytes\":{}}}",
            FOLD_ATTEMPTS.swap(0, Ordering::Relaxed),
            STRUCTURAL_ADMISSIONS.swap(0, Ordering::Relaxed),
            KEY_EVENTS.swap(0, Ordering::Relaxed),
            CAPTURE_MERGED_OPTIONS_THUNKS.swap(0, Ordering::Relaxed),
            CAPTURE_MERGED_OPTIONS_READY.swap(0, Ordering::Relaxed),
            CAPTURE_MERGED_OPTIONS_DECLINES.swap(0, Ordering::Relaxed),
            CAPTURE_ATTRSETS.swap(0, Ordering::Relaxed),
            CAPTURE_ENTRIES.swap(0, Ordering::Relaxed),
            CAPTURE_PROJECTION_ADMISSIONS.swap(0, Ordering::Relaxed),
            CAPTURE_PROJECTION_DECLINES.swap(0, Ordering::Relaxed),
            PROJECTED_PATH_ELEMENTS.swap(0, Ordering::Relaxed),
            PROJECTED_PATH_ELEMENT_STRINGS.swap(0, Ordering::Relaxed),
            PROJECTED_FINAL_VALUE_THUNKS.swap(0, Ordering::Relaxed),
            CALLBACK_FREE_EXECUTIONS.swap(0, Ordering::Relaxed),
            STAGE_A_ATTEMPTS.swap(0, Ordering::Relaxed),
            STAGE_A_ADMISSIONS.swap(0, Ordering::Relaxed),
            STAGE_A_EXACT_AGREEMENTS.swap(0, Ordering::Relaxed),
            STAGE_A_EXACT_ONLY.swap(0, Ordering::Relaxed),
            STAGE_A_GENERIC_ONLY.swap(0, Ordering::Relaxed),
            STAGE_A_BOTH_DECLINE.swap(0, Ordering::Relaxed),
            STAGE_A_REFERENCE_ERRORS.swap(0, Ordering::Relaxed),
            STAGE_A_CONTEXT_ERRORS.swap(0, Ordering::Relaxed),
            STAGE_A_CERTIFICATE_MISMATCHES.swap(0, Ordering::Relaxed),
            STAGE_A_REFERENCE
                .get()
                .map_or(0, StageATransducerCertificate::total_bytes),
        );
    }

    /// Peels an already-forced thunk chain without entering the force protocol.
    fn peek_final_config_forced_value(&self, value: Value) -> Option<Value> {
        const MAX_CHAIN_DEPTH: usize = 64;
        let mut current = value;
        for _ in 0..MAX_CHAIN_DEPTH {
            if current.tag() != ValueTag::Thunk {
                return Some(current);
            }
            if let Some(published) = self.heap.typed_thunk_published_value_if_any(current) {
                current = published?;
                continue;
            }
            current = self
                .heap
                .get_thunk(current)
                .ok()?
                .cell()
                .cached_value()
                .ok()??;
        }
        None
    }

    /// Projects the sole capture of an exact suspended alias thunk.
    fn project_final_config_alias_capture(
        &self,
        thunk: &EvalThunk,
        body: EvalNodeRef,
        env: &EvalEnv,
        plan: FinalConfigTriePlan,
    ) -> Option<Value> {
        if body.module() != self.current_module || body.id() != plan.option_map_alias_body {
            return None;
        }
        let site = env.flat_base()?.allocation_site();
        if site != EvalNodeRef::new(self.current_module, plan.option_map_alias_thunk_site) {
            return None;
        }
        match thunk.cell().state().ok()? {
            ThunkState::Suspended => self.captured_env_value_at_depth(
                env,
                plan.option_map_alias_decl_depth,
                plan.option_map_alias_decl_slot,
            ),
            ThunkState::Forced => thunk.cell().cached_value().ok()?,
            ThunkState::Blackhole => None,
        }
    }

    fn final_config_trie_runtime_enabled(&self) -> bool {
        self.tier1_engine.is_none()
            && !self.options.jit_tier1_publish_enabled()
            && !self.force_cache_active
            && !self.options.eval_cache_enabled()
            && !self.options.memo_active()
            && !self.options.boundary_memo_active()
            && self.options.heap_memory_budget().is_none()
            && self
                .options
                .heap_cheap_memory_advice_min_idle_epochs()
                .is_none()
            && !self.options.record_worker_closures_for_gc_scaffolding()
            && !self.options.eval_stats_dump()
            && !self.attr_update_telemetry_enabled
            && self.options.gc_mode() == EvalGcMode::Off
            && self.options.gc_stress_policy() == GcStressPolicy::disabled()
            && self.options.parallel_workers().is_none()
            && !self.options.parallel_thunk_payloads_enabled()
            && self.shared.is_none()
    }

    fn match_final_config_trie_fold(&self, fold: IrId) -> Option<FinalConfigTriePlan> {
        let exact = self.match_exact_final_config_trie_fold(fold);
        if report_enabled() {
            let generic = self.match_stage_a_transducer(fold, exact.is_some());
            STAGE_A_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            match (exact.is_some(), generic) {
                (true, true) => {
                    STAGE_A_EXACT_AGREEMENTS.fetch_add(1, Ordering::Relaxed);
                }
                (true, false) => {
                    STAGE_A_EXACT_ONLY.fetch_add(1, Ordering::Relaxed);
                }
                (false, true) => {
                    STAGE_A_GENERIC_ONLY.fetch_add(1, Ordering::Relaxed);
                }
                (false, false) => {
                    STAGE_A_BOTH_DECLINE.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        exact.or_else(|| {
            stage_b_enabled()
                .then(|| self.match_stage_b_transducer(fold))
                .flatten()
        })
    }

    /// Admits one source-unpinned but algorithm-pinned Stage-B fold.
    fn match_stage_b_transducer(&self, fold: IrId) -> Option<FinalConfigTriePlan> {
        let reference = STAGE_B_REFERENCE
            .get_or_init(trusted_stage_b_reference)
            .as_ref()?;
        let module = self.modules.get(self.current_module.index())?;
        let candidate = build_stage_a_reference(&module.ir, &self.symbols, fold)?;
        if &candidate != reference {
            return None;
        }
        self.match_source_unpinned_final_config_trie_fold(fold)
    }

    /// Compares a complete binder-selected fold graph with the checked primary
    /// reference without changing executable admission.
    fn match_stage_a_transducer(&self, fold: IrId, exact_admitted: bool) -> bool {
        let Some(module) = self.modules.get(self.current_module.index()) else {
            STAGE_A_CONTEXT_ERRORS.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let reference = if let Some(reference) = STAGE_A_REFERENCE.get() {
            reference
        } else if exact_admitted {
            let Some(reference) = build_stage_a_reference(&module.ir, &self.symbols, fold) else {
                STAGE_A_REFERENCE_ERRORS.fetch_add(1, Ordering::Relaxed);
                return false;
            };
            let _ = STAGE_A_REFERENCE.set(reference);
            let Some(reference) = STAGE_A_REFERENCE.get() else {
                STAGE_A_REFERENCE_ERRORS.fetch_add(1, Ordering::Relaxed);
                return false;
            };
            reference
        } else {
            STAGE_A_REFERENCE_ERRORS.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let Ok(candidate) =
            crate::compile::analyze_semantic_subslice_with_symbols(&module.ir, &self.symbols, fold)
        else {
            STAGE_A_CONTEXT_ERRORS.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        if candidate.canonical_bytes() != reference.fold.as_ref() {
            STAGE_A_CERTIFICATE_MISMATCHES.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        STAGE_A_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn match_exact_final_config_trie_fold(&self, fold: IrId) -> Option<FinalConfigTriePlan> {
        let module = self.modules.get(self.current_module.index())?;
        let source = module.source.as_ref()?;
        if !source.name.ends_with(b"/lib/modules.nix")
            || source.bytes.as_slice() != PRIMARY_MODULES_SOURCE
        {
            return None;
        }
        self.match_source_unpinned_final_config_trie_fold(fold)
    }

    /// Extracts the existing structural plan without consulting source identity.
    ///
    /// Stage B deliberately retains the exact helper names and merged-options
    /// slot constraint. The semantic certificate removes source-file pinning,
    /// not the algorithm pin.
    fn match_source_unpinned_final_config_trie_fold(
        &self,
        fold: IrId,
    ) -> Option<FinalConfigTriePlan> {
        let module = self.modules.get(self.current_module.index())?;
        let node = module.ir.arena.node(fold)?;
        if node.kind != IrKind::PrimOp {
            return None;
        }
        let IrData::PrimOp { symbol, args } = node.data else {
            return None;
        };
        if self.symbols.resolve(symbol)? != b"foldl'" {
            return None;
        }
        let [operator, initial, list] = module.ir.arena.child_slice(args)? else {
            return None;
        };
        let initial = module.ir.arena.node(*initial)?;
        let IrData::AttrSet {
            bindings: initial_bindings,
            ..
        } = initial.data
        else {
            return None;
        };
        if !initial_bindings.is_empty() {
            return None;
        }
        let operator = module.ir.arena.node(*operator)?;
        let IrData::Lambda { body, frame, .. } = operator.data else {
            return None;
        };
        frame?;
        let inner = module.ir.arena.node(body)?;
        let IrData::Lambda {
            body: inner_body,
            frame: inner_frame,
            ..
        } = inner.data
        else {
            return None;
        };
        inner_frame?;
        if module.ir.arena.node(inner_body)?.kind != IrKind::Let {
            return None;
        }
        let list = module.ir.arena.node(*list)?;
        let IrData::PrimOp {
            symbol: list_symbol,
            args: list_args,
        } = list.data
        else {
            return None;
        };
        if self.symbols.resolve(list_symbol)? != b"attrNames" {
            return None;
        }
        let [receiver] = module.ir.arena.child_slice(list_args)? else {
            return None;
        };
        let IrData::Local { slot } = module.ir.arena.node(*receiver)?.data else {
            return None;
        };
        if slot != PRIMARY_MERGED_OPTIONS_SLOT {
            return None;
        }
        let mut entry_records =
            module
                .ir
                .arena
                .nodes()
                .iter()
                .enumerate()
                .filter_map(|(id, candidate)| {
                    let thunk_site = IrId::new(u32::try_from(id).ok()?);
                    exact_entry_record_projection(&module.ir, &self.symbols, thunk_site, candidate)
                });
        let entry_record = entry_records.next()?;
        if entry_records.next().is_some() {
            return None;
        }
        let option_map_alias = exact_option_map_alias_projection(
            &module.ir,
            &self.symbols,
            entry_record.option_map_depth,
            entry_record.option_map_slot,
        )?;
        let deep_merge_construction =
            exact_deep_merge_attr_construction(&module.ir, &self.symbols)?;
        let set_path_construction = exact_set_path_attr_construction(&module.ir, &self.symbols)?;
        Some(FinalConfigTriePlan {
            capture_depth: 0,
            capture_slot: slot,
            entry_record_thunk_site: entry_record.thunk_site,
            entry_record_body: entry_record.body,
            entry_record_uses_flat_capture: entry_record.uses_flat_capture,
            path_owner_depth: entry_record.path_owner_depth,
            path_owner_slot: entry_record.path_owner_slot,
            final_value_depth: entry_record.final_value_depth,
            final_value_slot: entry_record.final_value_slot,
            path_symbol: entry_record.path_symbol,
            decl_thunk_site: entry_record.decl_thunk_site,
            decl_body: entry_record.decl_body,
            decl_key_depth: entry_record.decl_key_depth,
            decl_key_slot: entry_record.decl_key_slot,
            option_map_depth: entry_record.option_map_depth,
            option_map_slot: entry_record.option_map_slot,
            option_map_alias_thunk_site: option_map_alias.thunk_site,
            option_map_alias_body: option_map_alias.body,
            option_map_alias_decl_depth: option_map_alias.decl_depth,
            option_map_alias_decl_slot: option_map_alias.decl_slot,
            deep_merge_construction,
            set_path_construction,
        })
    }

    /// Validates that the runtime operator is the closure proved by the fold.
    fn final_config_fold_operator_matches(&self, fold: IrId, lambda: &EvalLambda) -> bool {
        if lambda.module() != self.current_module
            || !lambda.with_scope_env().is_empty()
            || !lambda.scoped_global_env().is_empty()
        {
            return false;
        }
        let Some(module) = self.modules.get(self.current_module.index()) else {
            return false;
        };
        let Some(fold_node) = module.ir.arena.node(fold) else {
            return false;
        };
        let IrData::PrimOp { args, .. } = fold_node.data else {
            return false;
        };
        let Some([operator, _, _]) = module.ir.arena.child_slice(args) else {
            return false;
        };
        let Some(operator) = module.ir.arena.node(*operator) else {
            return false;
        };
        let IrData::Lambda {
            pattern,
            body,
            frame: Some(frame),
        } = operator.data
        else {
            return false;
        };
        lambda.pattern() == pattern && lambda.body() == body && lambda.frame() == frame
    }
}

/// Builds the Stage-B reference without depending on candidate encounter order.
fn trusted_stage_b_reference() -> Option<StageATransducerCertificate> {
    let source = std::str::from_utf8(PRIMARY_MODULES_SOURCE).ok()?;
    let parsed = crate::syntax::parse_str(source).ok()?;
    let resolved = crate::compile::resolve(parsed).ok()?;
    let mut ir = aos_nix_dialect::nix_lower(resolved).ok()?;
    crate::compile::annotate_import_ir(&mut ir).ok()?;
    let evaluator = TreeWalk::with_options_and_source(
        &ir,
        TreeWalkOptions::default(),
        b"/trusted/lib/modules.nix",
        PRIMARY_MODULES_SOURCE,
    );
    let mut matches = ir.arena.nodes().iter().enumerate().filter_map(|(raw, _)| {
        let fold = IrId::new(u32::try_from(raw).ok()?);
        evaluator
            .match_exact_final_config_trie_fold(fold)
            .map(|_| fold)
    });
    let fold = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    build_stage_a_reference(&ir, &evaluator.symbols, fold)
}

fn build_stage_a_reference(
    ir: &Ir,
    symbols: &SymbolTable,
    fold: IrId,
) -> Option<StageATransducerCertificate> {
    let (deep_merge_site, deep_merge) = unique_named_thunk(ir, symbols, b"deepMerge")?;
    let (dedup_site, dedup) = unique_named_thunk(ir, symbols, b"dedup")?;
    let (set_path_site, set_path) = unique_named_thunk(ir, symbols, b"setPath")?;
    if !crate::compile::semantic_subslice_retains_all_with_symbols(
        ir,
        symbols,
        fold,
        &[deep_merge_site, dedup_site, set_path_site],
    )
    .ok()?
    {
        return None;
    }
    let fold = crate::compile::analyze_semantic_subslice_with_symbols(ir, symbols, fold).ok()?;
    let deep_merge =
        crate::compile::analyze_semantic_subslice_with_symbols(ir, symbols, deep_merge).ok()?;
    let dedup = crate::compile::analyze_semantic_subslice_with_symbols(ir, symbols, dedup).ok()?;
    let set_path =
        crate::compile::analyze_semantic_subslice_with_symbols(ir, symbols, set_path).ok()?;
    if !dedup
        .components()
        .iter()
        .any(crate::compile::SemanticBindingComponent::is_recursive)
    {
        return None;
    }
    Some(StageATransducerCertificate {
        fold: fold.canonical_bytes().into(),
        deep_merge: deep_merge.canonical_bytes().into(),
        dedup: dedup.canonical_bytes().into(),
        set_path: set_path.canonical_bytes().into(),
    })
}

#[derive(Clone, Copy, Debug)]
struct EntryRecordProjection {
    thunk_site: IrId,
    body: IrId,
    uses_flat_capture: bool,
    path_owner_depth: usize,
    path_owner_slot: u32,
    final_value_depth: usize,
    final_value_slot: u32,
    path_symbol: Symbol,
    decl_thunk_site: IrId,
    decl_body: IrId,
    decl_key_depth: usize,
    decl_key_slot: u32,
    option_map_depth: usize,
    option_map_slot: u32,
}

#[derive(Clone, Copy, Debug)]
struct OptionMapAliasProjection {
    thunk_site: IrId,
    body: IrId,
    decl_depth: usize,
    decl_slot: u32,
}

/// Finds the dynamic `listToAttrs` output and binding provenance in `deepMerge`.
fn exact_deep_merge_attr_construction(
    ir: &Ir,
    symbols: &SymbolTable,
) -> Option<FinalConfigAttrConstruction> {
    let function = unique_named_thunk_body(ir, symbols, b"deepMerge")?;
    let reachable = reachable_ir_nodes(ir, function)?;
    let mut matches = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(raw, node)| {
            if node.kind != IrKind::PrimOp || !reachable.get(raw).copied()? {
                return None;
            }
            let IrData::PrimOp { symbol, args } = node.data else {
                return None;
            };
            if symbols.resolve(symbol)? != b"listToAttrs" {
                return None;
            }
            let [mapped] = ir.arena.child_slice(args)? else {
                return None;
            };
            let mapped = ir.arena.node(*mapped)?;
            let IrData::PrimOp {
                symbol: map_symbol,
                args: map_args,
            } = mapped.data
            else {
                return None;
            };
            if mapped.kind != IrKind::PrimOp || symbols.resolve(map_symbol)? != b"map" {
                return None;
            }
            let [mapper, _] = ir.arena.child_slice(map_args)? else {
                return None;
            };
            let mapper = ir.arena.node(*mapper)?;
            let IrData::Lambda {
                body: record,
                frame: Some(_),
                ..
            } = mapper.data
            else {
                return None;
            };
            if mapper.kind != IrKind::Lambda {
                return None;
            }
            let record = ir.arena.node(record)?;
            let IrData::AttrSet {
                bindings,
                recursive: false,
                has_dynamic: false,
                ..
            } = record.data
            else {
                return None;
            };
            if record.kind != IrKind::AttrSet {
                return None;
            }
            let bindings = binding_slice(ir, bindings)?;
            if bindings.len() != 2 || named_binding(bindings, symbols, b"value").is_none() {
                return None;
            }
            let name = named_binding(bindings, symbols, b"name")?;
            Some(FinalConfigAttrConstruction {
                site: IrId::new(u32::try_from(raw).ok()?),
                shape: 0,
                binding_position: name.position,
            })
        });
    let projection = matches.next()?;
    matches.next().is_none().then_some(projection)
}

/// Finds the dynamic singleton attrset and binding provenance in `setPath`.
fn exact_set_path_attr_construction(
    ir: &Ir,
    symbols: &SymbolTable,
) -> Option<FinalConfigAttrConstruction> {
    let function = unique_named_thunk_body(ir, symbols, b"setPath")?;
    let reachable = reachable_ir_nodes(ir, function)?;
    let mut matches = ir
        .arena
        .nodes()
        .iter()
        .enumerate()
        .filter_map(|(raw, node)| {
            if node.kind != IrKind::AttrSet || !reachable.get(raw).copied()? {
                return None;
            }
            let IrData::AttrSet {
                shape,
                bindings,
                recursive: false,
                has_dynamic: true,
                ..
            } = node.data
            else {
                return None;
            };
            let [binding] = binding_slice(ir, bindings)? else {
                return None;
            };
            let IrAttrPathSegment::Dynamic(dynamic) = binding.key else {
                return None;
            };
            let dynamic = ir.arena.node(dynamic)?;
            let IrData::Node(key) = dynamic.data else {
                return None;
            };
            if dynamic.kind != IrKind::Interp {
                return None;
            }
            let key = ir.arena.node(key)?;
            let IrData::PrimOp { symbol, .. } = key.data else {
                return None;
            };
            if key.kind != IrKind::PrimOp || symbols.resolve(symbol)? != b"elemAt" {
                return None;
            }
            thunk_body(ir, binding.value)?;
            Some(FinalConfigAttrConstruction {
                site: IrId::new(u32::try_from(raw).ok()?),
                shape: shape.as_u32(),
                binding_position: binding.position,
            })
        });
    let projection = matches.next()?;
    matches.next().is_none().then_some(projection)
}

/// Finds one uniquely named lazy binding and returns its thunk body.
fn unique_named_thunk_body(ir: &Ir, symbols: &SymbolTable, name: &[u8]) -> Option<IrId> {
    unique_named_thunk(ir, symbols, name).map(|(_, body)| body)
}

/// Finds one uniquely named lazy binding and returns its site and body.
fn unique_named_thunk(ir: &Ir, symbols: &SymbolTable, name: &[u8]) -> Option<(IrId, IrId)> {
    let mut matches = ir.arena.nodes().iter().filter_map(|node| {
        let IrData::Let { bindings, .. } = node.data else {
            return None;
        };
        let binding = named_binding(binding_slice(ir, bindings)?, symbols, name)?;
        Some((binding.value, thunk_body(ir, binding.value)?))
    });
    let thunk = matches.next()?;
    matches.next().is_none().then_some(thunk)
}

/// Computes structural reachability from one named function body.
fn reachable_ir_nodes(ir: &Ir, root: IrId) -> Option<Vec<bool>> {
    let mut reachable = Vec::new();
    reachable.try_reserve_exact(ir.arena.nodes().len()).ok()?;
    reachable.resize(ir.arena.nodes().len(), false);
    let mut pending = Vec::new();
    pending.try_reserve(32).ok()?;
    pending.push(root);

    while let Some(id) = pending.pop() {
        let index = usize::try_from(id.as_u32()).ok()?;
        let seen = reachable.get_mut(index)?;
        if *seen {
            continue;
        }
        *seen = true;
        let node = ir.arena.node(id)?;
        match node.data {
            IrData::None
            | IrData::Int(_)
            | IrData::Float(_)
            | IrData::Bool(_)
            | IrData::Symbol(_)
            | IrData::GlobalVar { .. }
            | IrData::DialectScopeVar { .. }
            | IrData::Local { .. }
            | IrData::Upval { .. } => {}
            IrData::SearchPath { search_path, .. } => {
                pending.extend(search_path);
            }
            IrData::Node(child) => pending.push(child),
            IrData::Pair { first, second } => pending.extend([first, second]),
            IrData::Triple {
                first,
                second,
                third,
            } => pending.extend([first, second, third]),
            IrData::Children(children) => {
                pending.extend_from_slice(ir.arena.child_slice(children)?);
            }
            IrData::Bindings(bindings) => {
                for binding in binding_slice(ir, bindings)? {
                    pending.push(binding.value);
                    if let IrAttrPathSegment::Dynamic(key) = binding.key {
                        pending.push(key);
                    }
                }
            }
            IrData::Binary { lhs, rhs, .. } => pending.extend([lhs, rhs]),
            IrData::Unary { operand, .. } => pending.push(operand),
            IrData::Select {
                receiver,
                path,
                default,
                ..
            } => {
                pending.push(receiver);
                pending.extend(default);
                push_dynamic_attr_path(ir, path, &mut pending)?;
            }
            IrData::HasAttr { receiver, path, .. } => {
                pending.push(receiver);
                push_dynamic_attr_path(ir, path, &mut pending)?;
            }
            IrData::PrimOp { args, .. } => {
                pending.extend_from_slice(ir.arena.child_slice(args)?);
            }
            IrData::DialectNode { argument, .. } => pending.push(argument),
            IrData::Lambda { pattern, body, .. } => pending.extend([pattern, body]),
            IrData::Let { bindings, body, .. } => {
                pending.push(body);
                for binding in binding_slice(ir, bindings)? {
                    pending.push(binding.value);
                    if let IrAttrPathSegment::Dynamic(key) = binding.key {
                        pending.push(key);
                    }
                }
            }
            IrData::AttrSet { bindings, .. } => {
                for binding in binding_slice(ir, bindings)? {
                    pending.push(binding.value);
                    if let IrAttrPathSegment::Dynamic(key) = binding.key {
                        pending.push(key);
                    }
                }
            }
            IrData::FormalSet { formals, .. } => {
                pending.extend_from_slice(ir.arena.child_slice(formals)?);
            }
            IrData::Formal { default, .. } => pending.extend(default),
        }
    }
    Some(reachable)
}

/// Adds the expression nodes carried by one dynamic attribute path.
fn push_dynamic_attr_path(ir: &Ir, path: IrAttrPathId, pending: &mut Vec<IrId>) -> Option<()> {
    for segment in ir.attr_paths.get(path.index())?.iter() {
        if let IrAttrPathSegment::Dynamic(child) = segment {
            pending.push(*child);
        }
    }
    Some(())
}

#[cfg(test)]
fn final_config_path_is_proper_prefix(candidate: &[Vec<u8>], path: &[Vec<u8>]) -> bool {
    candidate.len() < path.len()
        && candidate
            .iter()
            .zip(path)
            .all(|(candidate, segment)| candidate == segment)
}

fn exact_entry_record_projection(
    ir: &Ir,
    symbols: &SymbolTable,
    thunk_site: IrId,
    node: &IrNode,
) -> Option<EntryRecordProjection> {
    let IrData::Node(body) = node.data else {
        return None;
    };
    if node.kind != IrKind::ThunkAlloc {
        return None;
    }
    let node = ir.arena.node(body)?;
    let IrData::AttrSet {
        bindings,
        recursive: false,
        has_dynamic: false,
        ..
    } = node.data
    else {
        return None;
    };
    if bindings.len != 4 {
        return None;
    }
    let Ok(start) = usize::try_from(bindings.start) else {
        return None;
    };
    let Some(end) = start.checked_add(4) else {
        return None;
    };
    let Some(bindings) = ir.bindings.get(start..end) else {
        return None;
    };
    let binding = |name: &[u8]| {
        bindings.iter().find(|binding| {
            let IrAttrPathSegment::Static(symbol) = binding.key else {
                return false;
            };
            symbols.resolve(symbol) == Some(name)
        })
    };
    let definitions_binding = binding(b"definitions")?;
    let option_binding = binding(b"option")?;
    let path_binding = binding(b"path")?;
    let final_value_binding = binding(b"finalValue")?;

    let (path_owner_depth, path_owner_slot, path_symbol) =
        select_owner_coordinate(ir, symbols, path_binding.value, b"path")?;
    let (option_owner_depth, option_owner_slot, _) =
        select_owner_coordinate(ir, symbols, option_binding.value, b"option")?;
    if (path_owner_depth, path_owner_slot) != (option_owner_depth, option_owner_slot) {
        return None;
    }
    let (final_value_depth, final_value_slot) =
        lexical_coordinate_through_alias(ir, final_value_binding.value)?;
    let (definitions_depth, definitions_slot) =
        lexical_coordinate_through_alias(ir, definitions_binding.value)?;
    if (path_owner_depth, path_owner_slot) == (final_value_depth, final_value_slot) {
        return None;
    }
    if (definitions_depth, definitions_slot) == (path_owner_depth, path_owner_slot)
        || (definitions_depth, definitions_slot) == (final_value_depth, final_value_slot)
    {
        return None;
    }

    let coordinates = [
        (path_owner_depth, path_owner_slot),
        (final_value_depth, final_value_slot),
        (definitions_depth, definitions_slot),
    ];
    let uses_flat_capture = match ir.facts.capture_plan(thunk_site)? {
        CapturePlan::Flat(captures) => {
            if captures.len() != coordinates.len()
                || coordinates.iter().any(|&(depth, slot)| {
                    !captures.iter().any(|capture| {
                        usize::from(capture.depth) == depth && u32::from(capture.slot) == slot
                    })
                })
            {
                return None;
            }
            true
        }
        CapturePlan::SharedChain(crate::compile::SharedChainReason::TooManyFreeVars) => false,
        CapturePlan::SharedChain(_) => return None,
    };
    let decl = exact_decl_projection(ir, symbols, thunk_site)?;
    if (path_owner_depth, path_owner_slot) != (0, decl.let_slot) {
        return None;
    }

    Some(EntryRecordProjection {
        thunk_site,
        body,
        uses_flat_capture,
        path_owner_depth,
        path_owner_slot,
        final_value_depth,
        final_value_slot,
        path_symbol,
        decl_thunk_site: decl.thunk_site,
        decl_body: decl.body,
        decl_key_depth: decl.key_depth,
        decl_key_slot: decl.key_slot,
        option_map_depth: decl.option_map_depth,
        option_map_slot: decl.option_map_slot,
    })
}

struct DeclProjection {
    let_slot: u32,
    thunk_site: IrId,
    body: IrId,
    key_depth: usize,
    key_slot: u32,
    option_map_depth: usize,
    option_map_slot: u32,
}

fn exact_decl_projection(
    ir: &Ir,
    symbols: &SymbolTable,
    entry_thunk_site: IrId,
) -> Option<DeclProjection> {
    let mut matches = ir.arena.nodes().iter().filter_map(|candidate| {
        let IrData::Let { bindings, body, .. } = candidate.data else {
            return None;
        };
        let body = ir.arena.node(body)?;
        let IrData::AttrSet {
            bindings: body_bindings,
            recursive: false,
            ..
        } = body.data
        else {
            return None;
        };
        let body_bindings = binding_slice(ir, body_bindings)?;
        let value_binding = named_binding(body_bindings, symbols, b"value")?;
        if value_binding.value != entry_thunk_site {
            return None;
        }
        let bindings = binding_slice(ir, bindings)?;
        let (decl_index, decl_binding) = bindings.iter().enumerate().find(|(_, binding)| {
            matches!(binding.key, IrAttrPathSegment::Static(symbol)
                if symbols.resolve(symbol) == Some(b"decl"))
        })?;
        let decl_thunk = ir.arena.node(decl_binding.value)?;
        let IrData::Node(decl_body) = decl_thunk.data else {
            return None;
        };
        if decl_thunk.kind != IrKind::ThunkAlloc {
            return None;
        }
        let select = ir.arena.node(decl_body)?;
        let IrData::Select {
            receiver,
            path,
            default: None,
            ..
        } = select.data
        else {
            return None;
        };
        let [IrAttrPathSegment::Dynamic(dynamic)] = ir.attr_paths.get(path.index())?.as_ref()
        else {
            return None;
        };
        let dynamic = ir.arena.node(*dynamic)?;
        let IrData::Node(key) = dynamic.data else {
            return None;
        };
        if dynamic.kind != IrKind::Interp {
            return None;
        }
        let (key_depth, key_slot) = lexical_coordinate(ir, key)?;
        let (option_map_depth, option_map_slot) = lexical_coordinate(ir, receiver)?;
        let CapturePlan::Flat(captures) = ir.facts.capture_plan(decl_binding.value)? else {
            return None;
        };
        if captures.len() != 2
            || [(key_depth, key_slot), (option_map_depth, option_map_slot)]
                .iter()
                .any(|&(depth, slot)| {
                    !captures.iter().any(|capture| {
                        usize::from(capture.depth) == depth && u32::from(capture.slot) == slot
                    })
                })
        {
            return None;
        }
        Some(DeclProjection {
            let_slot: u32::try_from(decl_index).ok()?,
            thunk_site: decl_binding.value,
            body: decl_body,
            key_depth,
            key_slot,
            option_map_depth,
            option_map_slot,
        })
    });
    let projection = matches.next()?;
    matches.next().is_none().then_some(projection)
}

fn exact_option_map_alias_projection(
    ir: &Ir,
    symbols: &SymbolTable,
    expected_option_map_depth: usize,
    expected_option_map_slot: u32,
) -> Option<OptionMapAliasProjection> {
    let mut matches = ir.arena.nodes().iter().filter_map(|candidate| {
        let IrData::Let {
            bindings,
            frame: Some(_),
            ..
        } = candidate.data
        else {
            return None;
        };
        let bindings = binding_slice(ir, bindings)?;
        let (option_map_index, option_map_binding) =
            named_binding_with_index(bindings, symbols, b"optionMap")?;
        if u32::try_from(option_map_index).ok()? != expected_option_map_slot
            || expected_option_map_depth != 2
        {
            return None;
        }
        let (all_decls_index, _) = named_binding_with_index(bindings, symbols, b"allOptionDecls")?;
        let all_decls_slot = u32::try_from(all_decls_index).ok()?;
        let fold = thunk_body(ir, option_map_binding.value)?;
        exact_option_map_fold_alias(ir, symbols, fold, all_decls_slot)
    });
    let projection = matches.next()?;
    matches.next().is_none().then_some(projection)
}

fn exact_option_map_fold_alias(
    ir: &Ir,
    symbols: &SymbolTable,
    fold: IrId,
    all_decls_slot: u32,
) -> Option<OptionMapAliasProjection> {
    let fold = ir.arena.node(fold)?;
    let IrData::PrimOp { symbol, args } = fold.data else {
        return None;
    };
    if fold.kind != IrKind::PrimOp || symbols.resolve(symbol)? != b"foldl'" {
        return None;
    }
    let [operator, initial, list] = ir.arena.child_slice(args)? else {
        return None;
    };
    let initial = ir.arena.node(*initial)?;
    let IrData::AttrSet {
        bindings: initial_bindings,
        recursive: false,
        has_dynamic: false,
        ..
    } = initial.data
    else {
        return None;
    };
    if initial.kind != IrKind::AttrSet || !initial_bindings.is_empty() {
        return None;
    }
    if lexical_coordinate(ir, *list)? != (0, all_decls_slot) {
        return None;
    }

    let operator = ir.arena.node(*operator)?;
    let IrData::Lambda {
        body: inner,
        frame: Some(_),
        ..
    } = operator.data
    else {
        return None;
    };
    if operator.kind != IrKind::Lambda {
        return None;
    }
    let inner = ir.arena.node(inner)?;
    let IrData::Lambda {
        body: body_let,
        frame: Some(_),
        ..
    } = inner.data
    else {
        return None;
    };
    if inner.kind != IrKind::Lambda {
        return None;
    }
    let body_let = ir.arena.node(body_let)?;
    let IrData::Let {
        bindings,
        body,
        frame: Some(_),
    } = body_let.data
    else {
        return None;
    };
    let bindings = binding_slice(ir, bindings)?;
    if bindings.len() != 1 {
        return None;
    }
    let (key_index, key_binding) = named_binding_with_index(bindings, symbols, b"key")?;
    if key_index != 0 {
        return None;
    }
    let key_body = thunk_body(ir, key_binding.value)?;
    let key_body = ir.arena.node(key_body)?;
    let IrData::PrimOp {
        symbol: key_symbol,
        args: key_args,
    } = key_body.data
    else {
        return None;
    };
    if key_body.kind != IrKind::PrimOp || symbols.resolve(key_symbol)? != b"concatStringsSep" {
        return None;
    }
    let [separator, path] = ir.arena.child_slice(key_args)? else {
        return None;
    };
    let separator_node = ir.arena.node(*separator)?;
    let IrData::Symbol(separator_symbol) = separator_node.data else {
        return None;
    };
    if separator_node.kind != IrKind::Str || symbols.resolve(separator_symbol)? != b"." {
        return None;
    }
    let (path_owner_depth, path_owner_slot, _) =
        direct_select_owner_coordinate(ir, symbols, *path, b"path")?;
    if (path_owner_depth, path_owner_slot) != (1, 0) {
        return None;
    }

    let body = ir.arena.node(body)?;
    let IrData::Binary {
        op: BinOpKind::Update,
        lhs,
        rhs,
    } = body.data
    else {
        return None;
    };
    if body.kind != IrKind::BinOp || lexical_coordinate(ir, lhs)? != (2, 0) {
        return None;
    }
    let rhs = ir.arena.node(rhs)?;
    let IrData::AttrSet {
        bindings,
        recursive: false,
        has_dynamic: true,
        ..
    } = rhs.data
    else {
        return None;
    };
    if rhs.kind != IrKind::AttrSet {
        return None;
    }
    let [binding] = binding_slice(ir, bindings)? else {
        return None;
    };
    let IrAttrPathSegment::Dynamic(dynamic_key) = binding.key else {
        return None;
    };
    let dynamic_key = ir.arena.node(dynamic_key)?;
    let IrData::Node(key) = dynamic_key.data else {
        return None;
    };
    if dynamic_key.kind != IrKind::Interp || lexical_coordinate(ir, key)? != (0, 0) {
        return None;
    }

    let alias_body = thunk_body(ir, binding.value)?;
    let (decl_depth, decl_slot) = lexical_coordinate(ir, alias_body)?;
    if (decl_depth, decl_slot) != (1, 0) {
        return None;
    }
    let CapturePlan::Flat(captures) = ir.facts.capture_plan(binding.value)? else {
        return None;
    };
    if captures.len() != 1
        || usize::from(captures[0].depth) != decl_depth
        || u32::from(captures[0].slot) != decl_slot
    {
        return None;
    }
    if ir
        .arena
        .nodes()
        .iter()
        .filter(|node| {
            node.kind == IrKind::ThunkAlloc
                && matches!(node.data, IrData::Node(body) if body == alias_body)
        })
        .take(2)
        .count()
        != 1
    {
        return None;
    }
    Some(OptionMapAliasProjection {
        thunk_site: binding.value,
        body: alias_body,
        decl_depth,
        decl_slot,
    })
}

fn binding_slice(ir: &Ir, slice: IrBindingSlice) -> Option<&[IrBinding]> {
    let start = usize::try_from(slice.start).ok()?;
    ir.bindings
        .get(start..start.checked_add(usize::try_from(slice.len).ok()?)?)
}

fn thunk_body(ir: &Ir, id: IrId) -> Option<IrId> {
    let thunk = ir.arena.node(id)?;
    let IrData::Node(body) = thunk.data else {
        return None;
    };
    (thunk.kind == IrKind::ThunkAlloc).then_some(body)
}

fn named_binding_with_index<'a>(
    bindings: &'a [IrBinding],
    symbols: &SymbolTable,
    name: &[u8],
) -> Option<(usize, &'a IrBinding)> {
    bindings.iter().enumerate().find(|(_, binding)| {
        matches!(binding.key, IrAttrPathSegment::Static(symbol)
            if symbols.resolve(symbol) == Some(name))
    })
}

fn named_binding<'a>(
    bindings: &'a [IrBinding],
    symbols: &SymbolTable,
    name: &[u8],
) -> Option<&'a IrBinding> {
    bindings.iter().find(|binding| {
        matches!(binding.key, IrAttrPathSegment::Static(symbol)
            if symbols.resolve(symbol) == Some(name))
    })
}

fn direct_select_owner_coordinate(
    ir: &Ir,
    symbols: &SymbolTable,
    id: IrId,
    expected_name: &[u8],
) -> Option<(usize, u32, Symbol)> {
    let select = ir.arena.node(id)?;
    let IrData::Select {
        receiver,
        path,
        default: None,
        ..
    } = select.data
    else {
        return None;
    };
    if select.kind != IrKind::Select {
        return None;
    }
    let [IrAttrPathSegment::Static(symbol)] = ir.attr_paths.get(path.index())?.as_ref() else {
        return None;
    };
    if symbols.resolve(*symbol)? != expected_name {
        return None;
    }
    let (depth, slot) = lexical_coordinate(ir, receiver)?;
    Some((depth, slot, *symbol))
}

fn select_owner_coordinate(
    ir: &Ir,
    symbols: &SymbolTable,
    id: IrId,
    expected_name: &[u8],
) -> Option<(usize, u32, Symbol)> {
    let thunk = ir.arena.node(id)?;
    let IrData::Node(body) = thunk.data else {
        return None;
    };
    if thunk.kind != IrKind::ThunkAlloc {
        return None;
    }
    let select = ir.arena.node(body)?;
    let IrData::Select {
        receiver,
        path,
        default: None,
        ..
    } = select.data
    else {
        return None;
    };
    let [IrAttrPathSegment::Static(symbol)] = ir.attr_paths.get(path.index())?.as_ref() else {
        return None;
    };
    if symbols.resolve(*symbol)? != expected_name {
        return None;
    }
    let (depth, slot) = lexical_coordinate(ir, receiver)?;
    Some((depth, slot, *symbol))
}

fn lexical_coordinate(ir: &Ir, id: IrId) -> Option<(usize, u32)> {
    let node = ir.arena.node(id)?;
    match node.data {
        IrData::Local { slot } if node.kind == IrKind::LocalVar => Some((0, slot)),
        IrData::Upval { depth, slot } if node.kind == IrKind::UpvalVar => {
            Some((usize::try_from(depth).ok()?, slot))
        }
        _ => None,
    }
}

fn lexical_coordinate_through_alias(ir: &Ir, id: IrId) -> Option<(usize, u32)> {
    let node = ir.arena.node(id)?;
    if node.kind == IrKind::ThunkAlloc {
        let IrData::Node(body) = node.data else {
            return None;
        };
        return lexical_coordinate(ir, body);
    }
    lexical_coordinate(ir, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::resolve as resolve_ast;
    use crate::eval::heap::TypedThunkForceClaim;
    use crate::syntax::parse_str;

    fn lowered_primary(source: &[u8]) -> Ir {
        let source = std::str::from_utf8(source).expect("test source is UTF-8");
        let mut ir = aos_nix_dialect::nix_lower(
            resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        crate::compile::annotate_import_ir(&mut ir).expect("import facts annotate");
        ir
    }

    fn unique_exact_fold(evaluator: &TreeWalk, ir: &Ir) -> IrId {
        let mut folds = ir.arena.nodes().iter().enumerate().filter_map(|(raw, _)| {
            let fold = IrId::new(raw as u32);
            evaluator
                .match_source_unpinned_final_config_trie_fold(fold)
                .map(|_| fold)
        });
        let fold = folds.next().expect("one structural final-config fold");
        assert!(folds.next().is_none(), "structural fold must be unique");
        fold
    }

    #[allow(unsafe_code)]
    fn publish_typed_test_head(evaluator: &mut TreeWalk, thunk: Value, result: Value) {
        let ptr = evaluator
            .heap
            .thunk_ptr(thunk)
            .expect("typed test thunk resolves");
        let parts = evaluator
            .heap
            .typed_thunk_force_parts(ptr)
            .expect("typed test force parts resolve")
            .expect("test thunk uses a typed head");
        // SAFETY: `parts` belongs to this evaluator's live heap, and the guard
        // is finished before the evaluator or its heap can be dropped.
        let TypedThunkForceClaim::Claimed(guard) =
            (unsafe { parts.begin_force() }).expect("suspended test head claims")
        else {
            panic!("fresh test head cannot already be forced");
        };
        let handle = guard.handle();
        let work = evaluator
            .heap
            .take_typed_thunk_work(ptr, handle)
            .expect("typed test work detaches");
        guard.finish(result).expect("typed test result publishes");
        evaluator
            .heap
            .release_taken_typed_thunk_work(ptr, handle)
            .expect("published test work releases");
        drop(work);
    }

    #[test]
    fn final_config_peek_follows_forced_typed_chain_and_stops_at_suspended_head() {
        let ir = lowered_primary(b"null");
        let mut options = TreeWalkOptions::new();
        options.set_typed_apply_thunk_heads_enabled(true);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let inner = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(ir.root))
            .expect("inner typed test allocation succeeds");
        let outer = evaluator
            .heap
            .alloc_thunk(EvalThunk::new(ir.root))
            .expect("outer typed test allocation succeeds");

        assert!(evaluator.peek_final_config_forced_value(outer).is_none());
        publish_typed_test_head(&mut evaluator, outer, inner);
        assert!(
            evaluator.peek_final_config_forced_value(outer).is_none(),
            "a forced typed alias chain stops at its suspended typed target"
        );
        publish_typed_test_head(&mut evaluator, inner, Value::int(42));
        assert_eq!(
            evaluator
                .peek_final_config_forced_value(outer)
                .and_then(|value| value.as_int().ok()),
            Some(42),
            "the authoritative stable heads expose both publications"
        );
    }

    #[cfg(feature = "evacuation_plan_probe")]
    #[test]
    fn evacuation_probe_schedule_parses_single_execution() {
        let schedule = EvacuationProbeSchedule::parse("160").expect("schedule parses");

        assert_eq!(schedule.executions, [160]);
        assert!(schedule.contains(160));
        assert!(!schedule.contains(159));
        assert!(!schedule.is_cadence());
    }

    #[cfg(feature = "evacuation_plan_probe")]
    #[test]
    fn evacuation_probe_schedule_sorts_and_deduplicates_cadence() {
        let schedule =
            EvacuationProbeSchedule::parse(" 224,160,192,160 ").expect("schedule parses");

        assert_eq!(schedule.executions, [160, 192, 224]);
        assert!(schedule.contains(160));
        assert!(schedule.contains(192));
        assert!(schedule.contains(224));
        assert!(!schedule.contains(193));
        assert!(schedule.is_cadence());
    }

    #[cfg(feature = "evacuation_plan_probe")]
    #[test]
    fn evacuation_probe_schedule_rejects_empty_invalid_and_zero_entries() {
        assert_eq!(EvacuationProbeSchedule::parse(""), None);
        assert_eq!(EvacuationProbeSchedule::parse("160,"), None);
        assert_eq!(EvacuationProbeSchedule::parse("160,nope"), None);
        assert_eq!(EvacuationProbeSchedule::parse("0,160"), None);
    }

    #[test]
    fn exact_primary_source_contains_one_matching_fold() {
        let source = std::str::from_utf8(PRIMARY_MODULES_SOURCE).expect("source is UTF-8");
        let mut ir = aos_nix_dialect::nix_lower(
            resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        crate::compile::annotate_import_ir(&mut ir).expect("import facts annotate");
        let evaluator = TreeWalk::with_options_and_source(
            &ir,
            TreeWalkOptions::default(),
            b"/source/lib/modules.nix",
            PRIMARY_MODULES_SOURCE,
        );
        let plans = ir
            .arena
            .nodes()
            .iter()
            .enumerate()
            .filter_map(|(id, _)| {
                evaluator
                    .match_final_config_trie_fold(IrId::new(id as u32))
                    .map(|plan| (IrId::new(id as u32), plan))
            })
            .collect::<Vec<_>>();
        assert_eq!(plans.len(), 1);
        let (fold, plan) = plans[0];
        let certificate = build_stage_a_reference(&ir, &evaluator.symbols, fold)
            .expect("primary fold and captured helper graph form a checked semantic certificate");
        assert!(!certificate.fold.is_empty());
        assert!(!certificate.deep_merge.is_empty());
        assert!(!certificate.dedup.is_empty());
        assert!(!certificate.set_path.is_empty());
        assert!(
            evaluator.match_stage_a_transducer(fold, true),
            "Stage A must agree with the existing exact primary plan"
        );
        assert_eq!((plan.path_owner_depth, plan.path_owner_slot), (0, 0));
        assert_eq!((plan.final_value_depth, plan.final_value_slot), (0, 10));
        assert_eq!((plan.decl_key_depth, plan.decl_key_slot), (1, 0));
        assert_eq!((plan.option_map_depth, plan.option_map_slot), (2, 5));
        assert_eq!(
            (
                plan.option_map_alias_decl_depth,
                plan.option_map_alias_decl_slot,
            ),
            (1, 0),
        );
        let alias_site = ir
            .arena
            .node(plan.option_map_alias_thunk_site)
            .expect("alias site exists");
        assert_eq!(alias_site.kind, IrKind::ThunkAlloc);
        assert!(matches!(
            alias_site.data,
            IrData::Node(body) if body == plan.option_map_alias_body
        ));
        let Some(CapturePlan::Flat(alias_captures)) =
            ir.facts.capture_plan(plan.option_map_alias_thunk_site)
        else {
            panic!("alias capture plan must be flat");
        };
        assert_eq!(alias_captures.len(), 1);
        assert_eq!(
            usize::from(alias_captures[0].depth),
            plan.option_map_alias_decl_depth,
        );
        assert_eq!(
            u32::from(alias_captures[0].slot),
            plan.option_map_alias_decl_slot,
        );
        assert_eq!(
            ir.arena
                .nodes()
                .iter()
                .filter(|node| {
                    node.kind == IrKind::ThunkAlloc
                        && matches!(
                            node.data,
                            IrData::Node(body) if body == plan.option_map_alias_body
                        )
                })
                .count(),
            1,
        );
        let deep_site = ir
            .arena
            .node(plan.deep_merge_construction.site)
            .expect("deepMerge allocation site exists");
        let IrData::PrimOp { symbol, .. } = deep_site.data else {
            panic!("deepMerge allocation site must be a primop");
        };
        assert_eq!(ir.symbols.resolve(symbol), Some(b"listToAttrs".as_slice()));
        assert!(plan.deep_merge_construction.binding_position.is_some());

        let set_path_site = ir
            .arena
            .node(plan.set_path_construction.site)
            .expect("setPath allocation site exists");
        let IrData::AttrSet {
            shape,
            has_dynamic: true,
            ..
        } = set_path_site.data
        else {
            panic!("setPath allocation site must be a dynamic attrset");
        };
        assert_eq!(shape.as_u32(), plan.set_path_construction.shape);
        assert!(plan.set_path_construction.binding_position.is_some());
    }

    #[test]
    fn stage_b_reference_boots_without_an_encountered_exact_candidate() {
        let reference =
            trusted_stage_b_reference().expect("bundled source builds a trusted reference");
        assert!(!reference.fold.is_empty());
        assert!(!reference.deep_merge.is_empty());
        assert!(!reference.dedup.is_empty());
        assert!(!reference.set_path.is_empty());
    }

    #[test]
    fn stage_b_admits_relocated_comment_equivalent_primary_source() {
        let mut relocated = b"# relocated Stage-B candidate\n\n".to_vec();
        relocated.extend_from_slice(PRIMARY_MODULES_SOURCE);
        relocated.extend_from_slice(b"\n# trailing candidate comment\n");
        let ir = lowered_primary(&relocated);
        let evaluator = TreeWalk::with_options_and_source(
            &ir,
            TreeWalkOptions::default(),
            b"/relocated/copied-modules.nix",
            relocated.as_slice(),
        );
        let fold = unique_exact_fold(&evaluator, &ir);

        assert!(
            evaluator.match_exact_final_config_trie_fold(fold).is_none(),
            "the exact source matcher remains source pinned"
        );
        assert!(
            evaluator.match_stage_b_transducer(fold).is_some(),
            "Stage B admits the complete relocated semantic certificate"
        );
    }

    #[test]
    fn stage_b_complete_certificate_rejects_a_helper_change() {
        let source = std::str::from_utf8(PRIMARY_MODULES_SOURCE).expect("source is UTF-8");
        let changed = source.replacen(
            "dedup [] combined;",
            "dedup [] (builtins.reverseList combined);",
            1,
        );
        assert_ne!(changed.as_bytes(), PRIMARY_MODULES_SOURCE);
        let ir = lowered_primary(changed.as_bytes());
        let evaluator = TreeWalk::with_options_and_source(
            &ir,
            TreeWalkOptions::default(),
            b"/relocated/copied-modules.nix",
            changed.as_bytes(),
        );
        let fold = unique_exact_fold(&evaluator, &ir);
        assert!(
            evaluator.match_stage_b_transducer(fold).is_none(),
            "a changed helper role must reject the complete certificate"
        );
    }

    #[test]
    fn final_config_fold_rejects_a_different_runtime_operator_body() {
        let ir = lowered_primary(PRIMARY_MODULES_SOURCE);
        let evaluator = TreeWalk::with_options_and_source(
            &ir,
            TreeWalkOptions::default(),
            b"/source/lib/modules.nix",
            PRIMARY_MODULES_SOURCE,
        );
        let fold = unique_exact_fold(&evaluator, &ir);
        let node = ir.arena.node(fold).expect("fold node exists");
        let IrData::PrimOp { args, .. } = node.data else {
            panic!("fold is a primop");
        };
        let [operator, _, _] = ir.arena.child_slice(args).expect("fold args exist") else {
            panic!("fold has three arguments");
        };
        let operator = ir.arena.node(*operator).expect("operator node exists");
        let IrData::Lambda {
            pattern,
            body,
            frame: Some(frame),
        } = operator.data
        else {
            panic!("operator is a framed lambda");
        };
        let matching = EvalLambda::new(pattern, body, frame, EvalEnv::default());
        assert!(evaluator.final_config_fold_operator_matches(fold, &matching));

        let mismatched = EvalLambda::new(
            pattern,
            IrId::new(body.as_u32() + 1),
            frame,
            EvalEnv::default(),
        );
        assert!(!evaluator.final_config_fold_operator_matches(fold, &mismatched));
    }

    fn stage_a_test_slice(source: &str) -> crate::compile::SemanticSlice {
        let ir = aos_nix_dialect::nix_lower(
            resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        let fold = ir
            .arena
            .nodes()
            .iter()
            .enumerate()
            .find_map(|(raw, node)| {
                let IrData::PrimOp { symbol, .. } = node.data else {
                    return None;
                };
                (ir.symbols.resolve(symbol) == Some(b"foldl'".as_slice()))
                    .then(|| IrId::new(raw as u32))
            })
            .expect("source contains a direct foldl' call");
        crate::compile::analyze_semantic_subslice(&ir, fold)
            .expect("fold has one sound lexical context")
    }

    fn stage_a_test_source(
        names: (&str, &str, &str, &str, &str),
        binding_order: &str,
        merge_result: &str,
        recursion_call: &str,
    ) -> String {
        let (dedup, set_path, deep_merge, source, operator) = names;
        format!(
            "let
               {binding_order}
               {dedup} = flag: if flag then {recursion_call} false else flag;
               {set_path} = path: value:
                 {{ ${{builtins.elemAt path 0}} = value; }};
               {deep_merge} = left: right:
                 if {dedup} false then right else {merge_result};
               {source} = {{}};
               {operator} = acc: key:
                 {deep_merge} acc ({set_path} [ key ] {source}.${{key}});
             in builtins.foldl' {operator} {{}} (builtins.attrNames {source})"
        )
    }

    #[test]
    fn stage_a_semantic_certificate_ignores_alpha_slots_and_unrelated_helpers() {
        let reference = stage_a_test_source(
            ("dedup", "setPath", "deepMerge", "source", "operator"),
            "",
            "left // right",
            "dedup",
        );
        let relocated = stage_a_test_source(
            ("walk", "singleton", "combine", "input", "step"),
            "unused = value: value; anotherUnused = 42;",
            "left // right",
            "walk",
        );
        assert_eq!(
            stage_a_test_slice(&reference),
            stage_a_test_slice(&relocated)
        );
    }

    #[test]
    fn stage_a_semantic_certificate_rejects_bias_and_recursion_changes() {
        let reference = stage_a_test_source(
            ("dedup", "setPath", "deepMerge", "source", "operator"),
            "",
            "left // right",
            "dedup",
        );
        let reversed = stage_a_test_source(
            ("dedup", "setPath", "deepMerge", "source", "operator"),
            "",
            "right // left",
            "dedup",
        );
        let changed_recursion = stage_a_test_source(
            ("dedup", "setPath", "deepMerge", "source", "operator"),
            "other = flag: flag;",
            "left // right",
            "other",
        );
        let reference = stage_a_test_slice(&reference);
        assert_ne!(reference, stage_a_test_slice(&reversed));
        assert_ne!(reference, stage_a_test_slice(&changed_recursion));
    }

    fn trie_symbols(names: &[&[u8]]) -> (SymbolTable, Vec<Symbol>) {
        let mut symbols = SymbolTable::new();
        let values = names
            .iter()
            .map(|name| symbols.intern(name).expect("test symbol interns"))
            .collect();
        (symbols, values)
    }

    fn resolved_keys(symbols: &SymbolTable, keys: &[Symbol]) -> Vec<Vec<u8>> {
        keys.iter()
            .map(|key| {
                symbols
                    .resolve(*key)
                    .expect("test symbol resolves")
                    .to_vec()
            })
            .collect()
    }

    #[test]
    fn trie_declines_duplicate_and_prefix_paths_in_both_orders() {
        let (_, keys) = trie_symbols(&[b"a", b"b"]);
        let [a, b] = keys.as_slice() else {
            panic!("test symbols");
        };

        let mut duplicate = FinalConfigTrieNode::default();
        duplicate
            .insert(&[*a, *b], Value::int(1))
            .expect("first duplicate path inserts");
        assert_eq!(
            duplicate.insert(&[*a, *b], Value::int(2)),
            Err(FinalConfigTrieDecline::DuplicatePath),
        );

        let mut short_first = FinalConfigTrieNode::default();
        short_first
            .insert(&[*a], Value::int(1))
            .expect("short path inserts");
        assert_eq!(
            short_first.insert(&[*a, *b], Value::int(2)),
            Err(FinalConfigTrieDecline::ProperPrefix),
        );

        let mut long_first = FinalConfigTrieNode::default();
        long_first
            .insert(&[*a, *b], Value::int(1))
            .expect("long path inserts");
        assert_eq!(
            long_first.insert(&[*a], Value::int(2)),
            Err(FinalConfigTrieDecline::ProperPrefix),
        );
        assert_eq!(
            FinalConfigTrieNode::default().insert(&[], Value::int(0)),
            Err(FinalConfigTrieDecline::EmptyPath),
        );
    }

    #[test]
    fn trie_reproduces_deep_merge_source_order() {
        let (symbols, keys) = trie_symbols(&[b"a", b"m", b"z"]);
        let [a, m, z] = keys.as_slice() else {
            panic!("test symbols");
        };

        let mut last_new = FinalConfigTrieNode::default();
        last_new.insert(&[*m], Value::int(1)).expect("m inserts");
        last_new.insert(&[*z], Value::int(2)).expect("z inserts");
        last_new
            .insert(&[*a], Value::int(3))
            .expect("a inserts last");
        let order = last_new
            .source_order_keys(&symbols)
            .expect("source order builds");
        assert_eq!(
            resolved_keys(&symbols, &order),
            [b"m".to_vec(), b"z".to_vec(), b"a".to_vec()],
        );

        let mut last_existing = FinalConfigTrieNode::default();
        last_existing
            .insert(&[*m, *a], Value::int(1))
            .expect("first m path inserts");
        last_existing
            .insert(&[*z], Value::int(2))
            .expect("z path inserts");
        last_existing
            .insert(&[*m, *z], Value::int(3))
            .expect("second m path inserts");
        let order = last_existing
            .source_order_keys(&symbols)
            .expect("source order builds");
        assert_eq!(
            resolved_keys(&symbols, &order),
            [b"m".to_vec(), b"z".to_vec()],
        );
    }

    #[test]
    fn trie_selects_deep_merge_and_set_path_position_classes() {
        let (_, keys) = trie_symbols(&[b"a", b"b", b"c", b"d", b"z"]);
        let [a, b, c, d, z] = keys.as_slice() else {
            panic!("test symbols");
        };
        let mut trie = FinalConfigTrieNode::default();
        trie.insert(&[*a, *b, *c], Value::int(1))
            .expect("first shared path inserts");
        trie.insert(&[*a, *b, *d], Value::int(2))
            .expect("second shared path inserts");
        trie.insert(&[*z, *c], Value::int(3))
            .expect("single branch inserts");

        assert_eq!(
            trie.construction_kind(true),
            FinalConfigConstructionKind::DeepMerge,
        );
        let FinalConfigTrieEdge::Node(a_node) = trie.children.get(a).expect("a node") else {
            panic!("a is a node");
        };
        assert_eq!(
            a_node.construction_kind(false),
            FinalConfigConstructionKind::DeepMerge,
        );
        let FinalConfigTrieEdge::Node(b_node) = a_node.children.get(b).expect("b node") else {
            panic!("b is a node");
        };
        assert_eq!(
            b_node.construction_kind(false),
            FinalConfigConstructionKind::DeepMerge,
        );
        let FinalConfigTrieEdge::Node(z_node) = trie.children.get(z).expect("z node") else {
            panic!("z is a node");
        };
        assert_eq!(
            z_node.construction_kind(false),
            FinalConfigConstructionKind::SetPath,
        );
    }

    #[test]
    fn projected_path_relations_keep_segments_distinct() {
        let dotted = vec![b"a.b".to_vec()];
        let split = vec![b"a".to_vec(), b"b".to_vec()];
        let child = vec![b"a.b".to_vec(), b"c".to_vec()];

        assert_ne!(dotted, split);
        assert!(final_config_path_is_proper_prefix(&dotted, &child));
        assert!(!final_config_path_is_proper_prefix(&split, &child));
        assert!(!final_config_path_is_proper_prefix(&dotted, &dotted));
    }

    #[test]
    fn nearby_source_change_fails_closed() {
        let source = std::str::from_utf8(PRIMARY_MODULES_SOURCE).expect("source is UTF-8");
        let ir = aos_nix_dialect::nix_lower(
            resolve_ast(parse_str(source).expect("source parses")).expect("source resolves"),
        )
        .expect("source lowers");
        let mut changed = PRIMARY_MODULES_SOURCE.to_vec();
        changed.push(b'\n');
        let evaluator = TreeWalk::with_options_and_source(
            &ir,
            TreeWalkOptions::default(),
            b"/source/lib/modules.nix",
            changed,
        );
        assert!(ir.arena.nodes().iter().enumerate().all(|(id, _)| {
            evaluator
                .match_final_config_trie_fold(IrId::new(id as u32))
                .is_none()
        }));
    }
}

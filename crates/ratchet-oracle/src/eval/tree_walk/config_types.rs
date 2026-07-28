//! Evaluator configuration types: `TreeWalkOptions` and its enums
//! (split from tree_walk.rs under the §2 file-size cap).
use super::*;
pub use aos_nix_compat::NixCompatProfile;

/// Default worker-record growth between Tier-B quiescent sweeps.
///
/// A sweep is considered at an evaluator quiescent point only after at least
/// this many thunks were allocated since the previous sweep. The default is
/// sized so sub-second evaluations (a package instantiate, `bench.wide` at
/// ~250k thunks) never pay for marking, while multi-million-thunk evaluations
/// (system toplevels, long-lived embedders) sweep a bounded number of times
/// with each cycle amortized against seconds of evaluation. Measured on
/// `bench.wide`: one sweep costs roughly 60-70ms and retires ~137k worker
/// records; capture shedding itself is time-neutral. Set
/// `AOS_NIX_GC_THRESHOLD=0` to sweep at every quiescent opportunity (the
/// stress cadence).
pub const DEFAULT_GC_SWEEP_THRESHOLD: u64 = 1_048_576;

/// Fixed admitted counts for the serial active packed-thunk experiment.
#[cfg(feature = "active_packed_thunk_probe")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivePackedThunkCapacities {
    /// Total Apply plus GenList thunk heads admitted for the evaluation.
    pub heads: usize,
    /// Total ordinary Apply work records admitted for the evaluation.
    pub apply: usize,
    /// Total exact GenListElemAtAddOne work records admitted for the evaluation.
    pub gen_list_elem_at_add_one: usize,
}

#[cfg(feature = "active_packed_thunk_probe")]
fn active_packed_thunk_capacities_from_env() -> Option<ActivePackedThunkCapacities> {
    const HEADS: &str = "AOS_NIX_ACTIVE_PACKED_THUNK_HEADS";
    const APPLY: &str = "AOS_NIX_ACTIVE_PACKED_THUNK_APPLY";
    const GEN_LIST: &str = "AOS_NIX_ACTIVE_PACKED_THUNK_GENLIST";
    let heads = std::env::var_os(HEADS);
    let apply = std::env::var_os(APPLY);
    let gen_list = std::env::var_os(GEN_LIST);
    if heads.is_none() && apply.is_none() && gen_list.is_none() {
        return None;
    }
    let parse = |name: &'static str, value: Option<std::ffi::OsString>| {
        value
            .unwrap_or_else(|| panic!("{name} is required when active packed thunks are enabled"))
            .to_str()
            .unwrap_or_else(|| panic!("{name} must be valid UTF-8"))
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("{name} must be a non-negative integer"))
    };
    Some(ActivePackedThunkCapacities {
        heads: parse(HEADS, heads),
        apply: parse(APPLY, apply),
        gen_list_elem_at_add_one: parse(GEN_LIST, gen_list),
    })
}

/// Runtime options used by the tree-walk evaluator.
///
/// These options carry interpreter settings that C++ Nix normally reads from
/// its process configuration, while keeping the Phase-1 oracle deterministic
/// and independent from ambient host state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeWalkOptions {
    pub(crate) nix_compat_profile: NixCompatProfile,
    pub(crate) reported_nix_version: Vec<u8>,
    pub(crate) store_dir: Vec<u8>,
    pub(crate) search_path_base: Vec<u8>,
    pub(crate) path_literal_base: Option<Vec<u8>>,
    pub(crate) home_dir: Option<Vec<u8>>,
    pub(crate) eval_mode: EvalMode,
    pub(crate) allowed_paths: Vec<Vec<u8>>,
    pub(crate) allowed_uris: Vec<Vec<u8>>,
    pub(crate) current_system: Option<Vec<u8>>,
    pub(crate) current_time: Option<i64>,
    pub(crate) trace_verbose: bool,
    pub(crate) abort_on_warn: bool,
    pub(crate) max_call_depth: usize,
    pub(crate) parse_toml_timestamps: bool,
    pub(crate) env_vars: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(crate) nix_path: Vec<NixSearchPathEntry>,
    pub(crate) corepkgs_path: Option<Vec<u8>>,
    pub(crate) reject_ambient_search_path: bool,
    pub(crate) reject_unconfigured_impure_builtin_constants: bool,
    pub(crate) parse_cache_root: Option<PathBuf>,
    pub(crate) persist_cache_root: Option<PathBuf>,
    pub(crate) eval_cache_enabled: bool,
    pub(crate) persist_cache_verify: bool,
    pub(crate) root_cutoff_enabled: bool,
    pub(crate) root_cutoff_check: bool,
    pub(crate) eval_stats_dump: bool,
    pub(crate) genlist_selected_child_census_enabled: bool,
    pub(crate) stg_session_enabled: bool,
    pub(crate) force_cache_materialization_costs: MaterializationCosts,
    pub(crate) heap_memory_budget: Option<HeapMemoryBudget>,
    pub(crate) heap_tier_b_transition_admission_enabled: bool,
    pub(crate) record_worker_closures_for_gc_scaffolding: bool,
    pub(crate) heap_thread_local_tier_a_enabled: bool,
    pub(crate) typed_apply_thunk_heads_enabled: bool,
    #[cfg(feature = "active_packed_thunk_probe")]
    pub(crate) active_packed_thunk_capacities: Option<ActivePackedThunkCapacities>,
    pub(crate) gc_stress_policy: GcStressPolicy,
    pub(crate) gc_mode: EvalGcMode,
    pub(crate) gc_sweep_threshold: u64,
    pub(crate) thunk_resolve_barrier_tier: GenerationalGcTier,
    pub(crate) parallel_thunk_payloads_enabled: bool,
    pub(crate) parallel_workers: Option<std::num::NonZeroUsize>,
    pub(crate) parallel_shape_projection: bool,
    pub(crate) attr_shape_mode: AttrShapeMode,
    pub(crate) jit_tier1_publish_enabled: bool,
    pub(crate) parallel_thunk_worker_id: ParallelThunkWorkerId,
    pub(crate) heap_cheap_memory_advice_min_idle_epochs: Option<u64>,
    pub(crate) flake_ref_resolutions: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(crate) memo: MemoOptions,
    pub(crate) memo_disk_locations: Vec<PersistDiskLocation>,
    pub(crate) memo_net: Option<MemoNetOptions>,
    pub(crate) boundary_memo: BoundaryMemoOptions,
    #[cfg(test)]
    pub(crate) fetch_tree_url_responses: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Default for TreeWalkOptions {
    fn default() -> Self {
        Self {
            nix_compat_profile: NixCompatProfile::default(),
            reported_nix_version: NixCompatProfile::default().stock_version().to_vec(),
            store_dir: DEFAULT_STORE_DIR.to_vec(),
            search_path_base: b"/".to_vec(),
            path_literal_base: None,
            home_dir: None,
            eval_mode: EvalMode::default(),
            allowed_paths: Vec::new(),
            allowed_uris: Vec::new(),
            current_system: None,
            current_time: None,
            trace_verbose: false,
            abort_on_warn: false,
            max_call_depth: DEFAULT_MAX_CALL_DEPTH,
            parse_toml_timestamps: false,
            env_vars: BTreeMap::new(),
            nix_path: Vec::new(),
            corepkgs_path: None,
            reject_ambient_search_path: false,
            reject_unconfigured_impure_builtin_constants: false,
            parse_cache_root: None,
            persist_cache_root: None,
            eval_cache_enabled: false,
            persist_cache_verify: false,
            root_cutoff_enabled: false,
            root_cutoff_check: false,
            eval_stats_dump: false,
            genlist_selected_child_census_enabled: false,
            stg_session_enabled: false,
            force_cache_materialization_costs: DEFAULT_FORCE_CACHE_MATERIALIZATION_COSTS,
            heap_memory_budget: None,
            heap_tier_b_transition_admission_enabled: false,
            record_worker_closures_for_gc_scaffolding: false,
            heap_thread_local_tier_a_enabled: false,
            typed_apply_thunk_heads_enabled: false,
            #[cfg(feature = "active_packed_thunk_probe")]
            active_packed_thunk_capacities: active_packed_thunk_capacities_from_env(),
            gc_stress_policy: GcStressPolicy::disabled(),
            gc_mode: EvalGcMode::Off,
            gc_sweep_threshold: DEFAULT_GC_SWEEP_THRESHOLD,
            thunk_resolve_barrier_tier: GenerationalGcTier::OneShotArena,
            parallel_thunk_payloads_enabled: false,
            parallel_workers: None,
            parallel_shape_projection: false,
            attr_shape_mode: AttrShapeMode::default(),
            jit_tier1_publish_enabled: false,
            parallel_thunk_worker_id: ParallelThunkWorkerId::FIRST,
            heap_cheap_memory_advice_min_idle_epochs: None,
            flake_ref_resolutions: BTreeMap::new(),
            memo: MemoOptions::default(),
            memo_disk_locations: Vec::new(),
            memo_net: None,
            boundary_memo: BoundaryMemoOptions::from_env(),
            #[cfg(test)]
            fetch_tree_url_responses: BTreeMap::new(),
        }
    }
}

/// Hidden-class shape strategy for heap attrset records (RFC-0007 §09).
///
/// Selected through `AOS_NIX_SHAPES` (`off` / `transient` / `record`).
/// Every mode produces byte-identical evaluation results; the mode changes
/// only how attrset selects are served.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AttrShapeMode {
    /// No shape projection: attrset records carry no projected shape id and
    /// every select uses the flat key-validated slot cache or binary search.
    Off,
    /// The L2-P4 baseline: allocations project shapes through the transition
    /// tree and shaped selects rebuild a transient [`ShapedAttrs`] view per
    /// lookup. Measured a net loss on the package corpus, retained as the
    /// comparison baseline while the record mode is calibrated.
    #[default]
    Transient,
    /// Heap-resident shaped layout: the projected shape id stored in the
    /// record at construction is the select guard, and the flat symbol-order
    /// payload is the slot layout itself - a shaped select is a shape-id
    /// compare plus a constant-offset entry load, with no transient view.
    /// Static literal sites resolve their shape once and reuse the handle,
    /// and same-key-set `//` results keep the left operand's shape id.
    Record,
}

/// Filesystem and impurity policy used by the tree-walk evaluator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EvalMode {
    /// Allows evaluator-time filesystem access without an allow-list.
    #[default]
    Impure,
    /// Restricts evaluator-time filesystem access to explicitly allowed paths.
    Restricted,
    /// Models pure evaluation by allowing only explicitly allowed paths.
    Pure,
}

/// A configured entry in the Nix search path used by `<...>` and `findFile`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NixSearchPathEntry {
    pub(crate) prefix: Vec<u8>,
    pub(crate) path: Vec<u8>,
}

impl NixSearchPathEntry {
    /// Creates a search-path entry from a lookup prefix and path.
    ///
    /// The empty prefix models bare search-path roots. The path text is kept
    /// as provided so `builtins.nixPath` reflects configured entries without
    /// normalizing their spelling.
    ///
    /// # Errors
    ///
    /// This constructor currently accepts all byte strings and does not fail.
    pub fn new(
        prefix: impl Into<Vec<u8>>,
        path: impl Into<Vec<u8>>,
    ) -> Result<Self, TreeWalkOptionsError> {
        Ok(Self {
            prefix: prefix.into(),
            path: path.into(),
        })
    }

    /// Returns the search-path prefix matched against lookup paths.
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    /// Returns the configured filesystem path for this search-path entry.
    pub fn path(&self) -> &[u8] {
        &self.path
    }
}

#[derive(Debug, Default)]
pub(crate) enum EvalStderr {
    #[default]
    Process,
    #[cfg(test)]
    Buffer(Vec<u8>),
}

impl EvalStderr {
    pub(crate) fn write_trace_line(&mut self, message: &[u8]) {
        match self {
            Self::Process => {
                let mut stderr = io::stderr().lock();
                let _ = stderr.write_all(TRACE_PREFIX);
                let _ = stderr.write_all(message);
                let _ = stderr.write_all(b"\n");
            }
            #[cfg(test)]
            Self::Buffer(buffer) => {
                buffer.extend_from_slice(TRACE_PREFIX);
                buffer.extend_from_slice(message);
                buffer.extend_from_slice(b"\n");
            }
        }
    }

    pub(crate) fn write_all(&mut self, bytes: &[u8]) {
        match self {
            Self::Process => {
                let mut stderr = io::stderr().lock();
                let _ = stderr.write_all(bytes);
            }
            #[cfg(test)]
            Self::Buffer(buffer) => buffer.extend_from_slice(bytes),
        }
    }

    #[cfg(test)]
    pub(crate) fn capture(&mut self) {
        *self = Self::Buffer(Vec::new());
    }

    #[cfg(test)]
    pub(crate) fn captured(&self) -> &[u8] {
        match self {
            Self::Process => &[],
            Self::Buffer(buffer) => buffer,
        }
    }
}

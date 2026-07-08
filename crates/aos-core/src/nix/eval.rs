//! The evaluation seam: turning Nix source into a `.drv` graph.
//!
//! [`NixEval`] abstracts only the *evaluation* phase of Nix: parsing `.nix`
//! files and reducing them to derivation files or JSON-rendered metadata. It
//! deliberately does not cover the build phase, which remains delegated to real
//! Nix through [`NixCli::realise`](crate::nix::NixCli::realise).
//!
//! The default implementation is [`NixCli`], the permanent
//! C++ Nix oracle and fallback. The native implementation lives in the
//! `aos-nix` crate so `aos-core` stays lightweight.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::ops::Range;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
#[cfg(feature = "native-eval")]
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;

use super::env::aos_nix_env;
#[cfg(feature = "native-eval")]
use super::store::read_drv_closure;
use crate::nix::NixCli;

#[cfg(feature = "native-eval")]
use aos_nix::eval::tree_walk::NixSearchPathEntry;
#[cfg(feature = "native-eval")]
use aos_nix::{
    NativeCliFallbackReason, NativeDrvClosure, NativeEvalError, NixNative,
    eval::{
        EvalMode, IfdRealizationError, IfdRealizer, MemoNetMode, MemoNetOptions, MemoOptions,
        TreeWalkOptions,
    },
    heap::HeapMemoryBudget,
};

/// A `.drv` closure produced by an evaluator without requiring filesystem reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrvClosure {
    root: PathBuf,
    drvs: BTreeMap<PathBuf, Vec<u8>>,
}

impl DrvClosure {
    /// Creates an in-memory `.drv` closure.
    pub fn new(root: PathBuf, drvs: BTreeMap<PathBuf, Vec<u8>>) -> Self {
        Self { root, drvs }
    }

    /// Returns the top-level `.drv` path selected by the instantiation request.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns in-memory `.drv` ATerm bytes by absolute `.drv` path.
    pub fn drvs(&self) -> &BTreeMap<PathBuf, Vec<u8>> {
        &self.drvs
    }

    /// Consumes the closure into its root path and `.drv` byte map.
    pub fn into_parts(self) -> (PathBuf, BTreeMap<PathBuf, Vec<u8>>) {
        (self.root, self.drvs)
    }
}

static NATIVE_MODE: OnceLock<NativeMode> = OnceLock::new();
#[cfg(feature = "native-eval")]
static NATIVE_VERIFY_MODE: OnceLock<NativeVerifyMode> = OnceLock::new();
#[cfg(feature = "native-eval")]
static NATIVE_FALLBACK_UNSUPPORTED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_FALLBACK_INTERNAL: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_SUCCESS_FILE_INSTANTIATION: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_SUCCESS_EXPRESSION_INSTANTIATION: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_SUCCESS_EXPRESSION_EVALUATION: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_SHADOW_DRV_MATCH: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_SHADOW_DRV_DIVERGENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_SHADOW_DRV_INCOMPLETE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_SHADOW_EXPRESSION_MATCH: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_SHADOW_EXPRESSION_DIVERGENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_SHADOW_EXPRESSION_INCOMPLETE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_VERIFY_DRV_MATCH: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_VERIFY_DRV_DIVERGENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_VERIFY_DRV_INCOMPLETE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_VERIFY_EXPRESSION_MATCH: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_VERIFY_EXPRESSION_DIVERGENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "native-eval")]
static NATIVE_VERIFY_EXPRESSION_INCOMPLETE: AtomicU64 = AtomicU64::new(0);

/// Native evaluator fallback counters captured for the current process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeFallbackStats {
    unsupported: u64,
    internal: u64,
}

impl NativeFallbackStats {
    /// Returns fallbacks caused by explicitly unsupported native-evaluator features.
    pub const fn unsupported(&self) -> u64 {
        self.unsupported
    }

    /// Returns fallbacks caused by native-evaluator internal failures.
    pub const fn internal(&self) -> u64 {
        self.internal
    }

    /// Returns the total number of native-evaluator fallbacks.
    pub const fn total(&self) -> u64 {
        self.unsupported.saturating_add(self.internal)
    }
}

/// Authoritative native evaluator success counters captured for the current process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeSuccessStats {
    file_instantiations: u64,
    expression_instantiations: u64,
    expression_evaluations: u64,
}

impl NativeSuccessStats {
    /// Returns file-backed derivation instantiations completed by authoritative native eval.
    pub const fn file_instantiations(&self) -> u64 {
        self.file_instantiations
    }

    /// Returns expression-backed derivation instantiations completed by authoritative native eval.
    pub const fn expression_instantiations(&self) -> u64 {
        self.expression_instantiations
    }

    /// Returns strict JSON expression evaluations completed by authoritative native eval.
    pub const fn expression_evaluations(&self) -> u64 {
        self.expression_evaluations
    }

    /// Returns the total number of successful native-evaluator operations.
    pub const fn total(&self) -> u64 {
        self.file_instantiations
            .saturating_add(self.expression_instantiations)
            .saturating_add(self.expression_evaluations)
    }
}

/// Shadow-mode native evaluator comparison counters captured for the current process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeShadowStats {
    drv_matches: u64,
    drv_divergences: u64,
    drv_incomplete: u64,
    expression_matches: u64,
    expression_divergences: u64,
    expression_incomplete: u64,
}

impl NativeShadowStats {
    /// Returns `.drv` closure comparisons that matched C++ Nix.
    pub const fn drv_matches(&self) -> u64 {
        self.drv_matches
    }

    /// Returns `.drv` closure comparisons that diverged from C++ Nix.
    pub const fn drv_divergences(&self) -> u64 {
        self.drv_divergences
    }

    /// Returns `.drv` closure comparisons where either side could not be compared.
    pub const fn drv_incomplete(&self) -> u64 {
        self.drv_incomplete
    }

    /// Returns strict JSON expression comparisons that matched C++ Nix.
    pub const fn expression_matches(&self) -> u64 {
        self.expression_matches
    }

    /// Returns strict JSON expression comparisons that diverged from C++ Nix.
    pub const fn expression_divergences(&self) -> u64 {
        self.expression_divergences
    }

    /// Returns strict JSON expression comparisons where native eval did not complete.
    pub const fn expression_incomplete(&self) -> u64 {
        self.expression_incomplete
    }

    /// Returns the total number of completed shadow comparisons that matched.
    pub const fn matches(&self) -> u64 {
        self.drv_matches.saturating_add(self.expression_matches)
    }

    /// Returns the total number of completed shadow comparisons that diverged.
    pub const fn divergences(&self) -> u64 {
        self.drv_divergences
            .saturating_add(self.expression_divergences)
    }

    /// Returns the total number of shadow comparisons that could not complete.
    pub const fn incomplete(&self) -> u64 {
        self.drv_incomplete
            .saturating_add(self.expression_incomplete)
    }

    /// Returns the total number of shadow comparison attempts.
    pub const fn total(&self) -> u64 {
        self.matches()
            .saturating_add(self.divergences())
            .saturating_add(self.incomplete())
    }
}

/// Verify-mode native evaluator comparison counters captured for the current process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeVerifyStats {
    drv_matches: u64,
    drv_divergences: u64,
    drv_incomplete: u64,
    expression_matches: u64,
    expression_divergences: u64,
    expression_incomplete: u64,
}

impl NativeVerifyStats {
    /// Returns sampled `.drv` closure comparisons that matched C++ Nix.
    pub const fn drv_matches(&self) -> u64 {
        self.drv_matches
    }

    /// Returns sampled `.drv` closure comparisons that diverged from C++ Nix.
    pub const fn drv_divergences(&self) -> u64 {
        self.drv_divergences
    }

    /// Returns sampled `.drv` closure comparisons where either side could not be compared.
    pub const fn drv_incomplete(&self) -> u64 {
        self.drv_incomplete
    }

    /// Returns sampled strict JSON expression comparisons that matched C++ Nix.
    pub const fn expression_matches(&self) -> u64 {
        self.expression_matches
    }

    /// Returns sampled strict JSON expression comparisons that diverged from C++ Nix.
    pub const fn expression_divergences(&self) -> u64 {
        self.expression_divergences
    }

    /// Returns sampled strict JSON expression comparisons where C++ Nix could not be checked.
    pub const fn expression_incomplete(&self) -> u64 {
        self.expression_incomplete
    }

    /// Returns the total number of completed verify comparisons that matched.
    pub const fn matches(&self) -> u64 {
        self.drv_matches.saturating_add(self.expression_matches)
    }

    /// Returns the total number of completed verify comparisons that diverged.
    pub const fn divergences(&self) -> u64 {
        self.drv_divergences
            .saturating_add(self.expression_divergences)
    }

    /// Returns the total number of verify comparisons that could not complete.
    pub const fn incomplete(&self) -> u64 {
        self.drv_incomplete
            .saturating_add(self.expression_incomplete)
    }

    /// Returns the total number of verify comparison attempts.
    pub const fn total(&self) -> u64 {
        self.matches()
            .saturating_add(self.divergences())
            .saturating_add(self.incomplete())
    }
}

/// Native evaluator counters captured for the current process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeEvalStats {
    successes: NativeSuccessStats,
    fallbacks: NativeFallbackStats,
    shadow: NativeShadowStats,
    verify: NativeVerifyStats,
}

impl NativeEvalStats {
    /// Returns authoritative native operations that completed without falling back to C++ Nix.
    pub const fn successes(&self) -> NativeSuccessStats {
        self.successes
    }

    /// Returns native operations that fell back to C++ Nix.
    pub const fn fallbacks(&self) -> NativeFallbackStats {
        self.fallbacks
    }

    /// Returns shadow-mode native comparisons against C++ Nix.
    pub const fn shadow(&self) -> NativeShadowStats {
        self.shadow
    }

    /// Returns verify-mode native comparisons against C++ Nix.
    pub const fn verify(&self) -> NativeVerifyStats {
        self.verify
    }
}

/// Native strict-JSON evaluator counters captured for one expression evaluation.
///
/// These counters are returned by [`NixEval::eval_expr_with_stats`] when the
/// selected evaluator can report same-run tree-walk statistics. The heap fields
/// distinguish worker-domain Tier-A allocations from permanent shared
/// allocations so diff reports can prove which native memory domains were used
/// without running the candidate expression twice. The Tier-B admission fields
/// mirror the latest metadata-only heap admission report when a memory budget
/// triggers automatic admission.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NixEvalStrictJsonStats {
    thunks_forced: u64,
    thunks_allocated: u64,
    gc_bytes: u64,
    gc_pause_us: u64,
    tier_promotions: u64,
    deopts: u64,
    heap_chunks: u64,
    heap_reserved_bytes: u64,
    heap_mapped_bytes: u64,
    heap_used_bytes: u64,
    permanent_heap_chunks: u64,
    permanent_heap_reserved_bytes: u64,
    permanent_heap_mapped_bytes: u64,
    permanent_heap_used_bytes: u64,
    heap_tier_b_admission_worker_records: u64,
    heap_tier_b_admission_permanent_shared_records: u64,
    heap_tier_b_admission_generation_rewrites: u64,
}

impl NixEvalStrictJsonStats {
    /// Creates strict-JSON evaluator stats from explicit counter values.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        thunks_forced: u64,
        thunks_allocated: u64,
        gc_bytes: u64,
        gc_pause_us: u64,
        tier_promotions: u64,
        deopts: u64,
        heap_chunks: u64,
        heap_reserved_bytes: u64,
        heap_mapped_bytes: u64,
        heap_used_bytes: u64,
        permanent_heap_chunks: u64,
        permanent_heap_reserved_bytes: u64,
        permanent_heap_mapped_bytes: u64,
        permanent_heap_used_bytes: u64,
        heap_tier_b_admission_worker_records: u64,
        heap_tier_b_admission_permanent_shared_records: u64,
        heap_tier_b_admission_generation_rewrites: u64,
    ) -> Self {
        Self {
            thunks_forced,
            thunks_allocated,
            gc_bytes,
            gc_pause_us,
            tier_promotions,
            deopts,
            heap_chunks,
            heap_reserved_bytes,
            heap_mapped_bytes,
            heap_used_bytes,
            permanent_heap_chunks,
            permanent_heap_reserved_bytes,
            permanent_heap_mapped_bytes,
            permanent_heap_used_bytes,
            heap_tier_b_admission_worker_records,
            heap_tier_b_admission_permanent_shared_records,
            heap_tier_b_admission_generation_rewrites,
        }
    }

    #[cfg(feature = "native-eval")]
    fn from_native(stats: aos_nix::eval::EvalStats) -> Self {
        Self::new(
            stats.thunks_forced(),
            stats.thunks_allocated(),
            stats.gc_bytes(),
            stats.gc_pause_us(),
            stats.tier_promotions(),
            stats.deopts(),
            stats.heap_chunks(),
            stats.heap_reserved_bytes(),
            stats.heap_mapped_bytes(),
            stats.heap_used_bytes(),
            stats.permanent_heap_chunks(),
            stats.permanent_heap_reserved_bytes(),
            stats.permanent_heap_mapped_bytes(),
            stats.permanent_heap_used_bytes(),
            stats.heap_tier_b_admission_worker_records(),
            stats.heap_tier_b_admission_permanent_shared_records(),
            stats.heap_tier_b_admission_generation_rewrites(),
        )
    }

    /// Returns the number of thunks forced during strict JSON evaluation.
    pub const fn thunks_forced(&self) -> u64 {
        self.thunks_forced
    }

    /// Returns the number of thunks allocated during strict JSON evaluation.
    pub const fn thunks_allocated(&self) -> u64 {
        self.thunks_allocated
    }

    /// Returns bytes attributed to evaluator GC work.
    pub const fn gc_bytes(&self) -> u64 {
        self.gc_bytes
    }

    /// Returns microseconds spent in evaluator GC work.
    pub const fn gc_pause_us(&self) -> u64 {
        self.gc_pause_us
    }

    /// Returns optimized-tier promotions observed during evaluation.
    pub const fn tier_promotions(&self) -> u64 {
        self.tier_promotions
    }

    /// Returns optimized-tier deoptimizations observed during evaluation.
    pub const fn deopts(&self) -> u64 {
        self.deopts
    }

    /// Returns the number of worker bump-arena chunks allocated.
    pub const fn heap_chunks(&self) -> u64 {
        self.heap_chunks
    }

    /// Returns bytes reserved by worker evaluator heap chunks.
    pub const fn heap_reserved_bytes(&self) -> u64 {
        self.heap_reserved_bytes
    }

    /// Returns page-rounded bytes mapped by the worker evaluator heap arena.
    pub const fn heap_mapped_bytes(&self) -> u64 {
        self.heap_mapped_bytes
    }

    /// Returns bytes consumed by worker evaluator heap allocations.
    pub const fn heap_used_bytes(&self) -> u64 {
        self.heap_used_bytes
    }

    /// Returns the number of permanent shared bump-arena chunks allocated.
    pub const fn permanent_heap_chunks(&self) -> u64 {
        self.permanent_heap_chunks
    }

    /// Returns bytes reserved by permanent shared evaluator heap chunks.
    pub const fn permanent_heap_reserved_bytes(&self) -> u64 {
        self.permanent_heap_reserved_bytes
    }

    /// Returns page-rounded bytes mapped by the permanent shared evaluator heap arena.
    pub const fn permanent_heap_mapped_bytes(&self) -> u64 {
        self.permanent_heap_mapped_bytes
    }

    /// Returns bytes consumed by permanent shared evaluator heap allocations.
    pub const fn permanent_heap_used_bytes(&self) -> u64 {
        self.permanent_heap_used_bytes
    }

    /// Returns worker-domain heap records counted by the latest Tier-B admission.
    pub const fn heap_tier_b_admission_worker_records(&self) -> u64 {
        self.heap_tier_b_admission_worker_records
    }

    /// Returns permanent-shared heap records counted by the latest Tier-B admission.
    pub const fn heap_tier_b_admission_permanent_shared_records(&self) -> u64 {
        self.heap_tier_b_admission_permanent_shared_records
    }

    /// Returns heap-record generation metadata rewrites from the latest Tier-B admission.
    pub const fn heap_tier_b_admission_generation_rewrites(&self) -> u64 {
        self.heap_tier_b_admission_generation_rewrites
    }
}

/// Returns native evaluator fallback counters captured for the current process.
pub fn native_fallback_stats() -> NativeFallbackStats {
    #[cfg(feature = "native-eval")]
    {
        NativeFallbackStats {
            unsupported: NATIVE_FALLBACK_UNSUPPORTED.load(Ordering::Relaxed),
            internal: NATIVE_FALLBACK_INTERNAL.load(Ordering::Relaxed),
        }
    }

    #[cfg(not(feature = "native-eval"))]
    {
        NativeFallbackStats::default()
    }
}

/// Returns authoritative native evaluator success counters captured for the current process.
pub fn native_success_stats() -> NativeSuccessStats {
    #[cfg(feature = "native-eval")]
    {
        NativeSuccessStats {
            file_instantiations: NATIVE_SUCCESS_FILE_INSTANTIATION.load(Ordering::Relaxed),
            expression_instantiations: NATIVE_SUCCESS_EXPRESSION_INSTANTIATION
                .load(Ordering::Relaxed),
            expression_evaluations: NATIVE_SUCCESS_EXPRESSION_EVALUATION.load(Ordering::Relaxed),
        }
    }

    #[cfg(not(feature = "native-eval"))]
    {
        NativeSuccessStats::default()
    }
}

/// Returns shadow-mode native evaluator comparison counters captured for the current process.
pub fn native_shadow_stats() -> NativeShadowStats {
    #[cfg(feature = "native-eval")]
    {
        NativeShadowStats {
            drv_matches: NATIVE_SHADOW_DRV_MATCH.load(Ordering::Relaxed),
            drv_divergences: NATIVE_SHADOW_DRV_DIVERGENCE.load(Ordering::Relaxed),
            drv_incomplete: NATIVE_SHADOW_DRV_INCOMPLETE.load(Ordering::Relaxed),
            expression_matches: NATIVE_SHADOW_EXPRESSION_MATCH.load(Ordering::Relaxed),
            expression_divergences: NATIVE_SHADOW_EXPRESSION_DIVERGENCE.load(Ordering::Relaxed),
            expression_incomplete: NATIVE_SHADOW_EXPRESSION_INCOMPLETE.load(Ordering::Relaxed),
        }
    }

    #[cfg(not(feature = "native-eval"))]
    {
        NativeShadowStats::default()
    }
}

/// Returns verify-mode native evaluator comparison counters captured for the current process.
pub fn native_verify_stats() -> NativeVerifyStats {
    #[cfg(feature = "native-eval")]
    {
        NativeVerifyStats {
            drv_matches: NATIVE_VERIFY_DRV_MATCH.load(Ordering::Relaxed),
            drv_divergences: NATIVE_VERIFY_DRV_DIVERGENCE.load(Ordering::Relaxed),
            drv_incomplete: NATIVE_VERIFY_DRV_INCOMPLETE.load(Ordering::Relaxed),
            expression_matches: NATIVE_VERIFY_EXPRESSION_MATCH.load(Ordering::Relaxed),
            expression_divergences: NATIVE_VERIFY_EXPRESSION_DIVERGENCE.load(Ordering::Relaxed),
            expression_incomplete: NATIVE_VERIFY_EXPRESSION_INCOMPLETE.load(Ordering::Relaxed),
        }
    }

    #[cfg(not(feature = "native-eval"))]
    {
        NativeVerifyStats::default()
    }
}

/// Returns native evaluator counters captured for the current process.
pub fn native_eval_stats() -> NativeEvalStats {
    NativeEvalStats {
        successes: native_success_stats(),
        fallbacks: native_fallback_stats(),
        shadow: native_shadow_stats(),
        verify: native_verify_stats(),
    }
}

/// An evaluator that reduces Nix source to derivations or JSON-rendered values.
///
/// Implementations must produce byte-identical `.drv` files and store paths to
/// C++ Nix for every input AOS evaluates. A divergent `.drv` is a correctness
/// bug because it changes output store paths and can force rebuilds.
pub trait NixEval: Send + Sync {
    /// Evaluates `attr` from `file`, writes the derivation closure to the store,
    /// and returns the top-level `.drv` path.
    ///
    /// # Errors
    ///
    /// Returns an error when parsing, evaluation, or `.drv` materialization
    /// fails.
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf>;

    /// Evaluates a raw Nix expression to a derivation and returns its `.drv`
    /// path.
    ///
    /// # Errors
    ///
    /// Returns an error when parsing, evaluation, or `.drv` materialization
    /// fails.
    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf>;

    /// Evaluates a raw expression to a derivation path with caller-selected diagnostics.
    ///
    /// Evaluators that can remap source spans should render errors that land
    /// inside `diagnostic_range` against `diagnostic_name` and
    /// `diagnostic_source`. Evaluators without source-remapping support may
    /// ignore the diagnostic arguments and call [`Self::instantiate_expr`].
    ///
    /// # Errors
    ///
    /// Returns an error when parsing, evaluation, or `.drv` materialization
    /// fails.
    fn instantiate_expr_with_diagnostic_source(
        &self,
        expr: &str,
        diagnostic_name: &str,
        diagnostic_source: &str,
        diagnostic_range: Range<usize>,
    ) -> Result<PathBuf> {
        let _ = (diagnostic_name, diagnostic_source, diagnostic_range);
        self.instantiate_expr(expr)
    }

    /// Evaluates `attr` from `file` to an in-memory `.drv` closure when
    /// supported by this evaluator.
    ///
    /// File-backed evaluators return `Ok(None)`, allowing consumers to call
    /// [`Self::instantiate`] and read the resulting closure from the filesystem.
    /// Native diff candidates return `Some` so byte comparison is tied to the
    /// same native evaluation that selected the root path.
    ///
    /// # Errors
    ///
    /// Returns an error when parsing, evaluation, or in-memory `.drv`
    /// materialization fails.
    fn instantiate_closure(&self, file: &Path, attr: &str) -> Result<Option<DrvClosure>> {
        let _ = (file, attr);
        Ok(None)
    }

    /// Evaluates a raw expression with `--strict --json` rendering semantics.
    ///
    /// # Errors
    ///
    /// Returns an error when parsing, evaluation, or JSON rendering fails.
    fn eval_expr(&self, expr: &str) -> Result<String>;

    /// Evaluates a raw expression with strict JSON semantics and optional stats.
    ///
    /// Implementations that return stats must capture them from the same
    /// evaluator run that produced the returned JSON text. Implementations that
    /// cannot report same-run counters return `None`.
    ///
    /// # Errors
    ///
    /// Returns an error when parsing, evaluation, or JSON rendering fails.
    fn eval_expr_with_stats(&self, expr: &str) -> Result<(String, Option<NixEvalStrictJsonStats>)> {
        self.eval_expr(expr).map(|value| (value, None))
    }

    /// Evaluates a raw expression with caller-selected diagnostic source text.
    ///
    /// Evaluators that can remap source spans should render errors that land
    /// inside `diagnostic_range` against `diagnostic_name` and
    /// `diagnostic_source`. Evaluators without source-remapping support may
    /// ignore the diagnostic arguments and call [`Self::eval_expr`].
    ///
    /// # Errors
    ///
    /// Returns an error when parsing, evaluation, or JSON rendering fails.
    fn eval_expr_with_diagnostic_source(
        &self,
        expr: &str,
        diagnostic_name: &str,
        diagnostic_source: &str,
        diagnostic_range: Range<usize>,
    ) -> Result<String> {
        let _ = (diagnostic_name, diagnostic_source, diagnostic_range);
        self.eval_expr(expr)
    }

    /// Returns a stable implementation name for diagnostics and tracing.
    fn name(&self) -> &'static str;
}

/// Evaluation impurity mode shared by native and C++ Nix evaluators.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NixEvalMode {
    /// Leaves C++ Nix to use its ambient configured evaluation policy.
    #[default]
    Ambient,
    /// Forces evaluator-time access using C++ Nix's ordinary impure mode.
    Impure,
    /// Enables `restrict-eval` and checks filesystem and URI allowlists.
    Restricted,
    /// Enables `pure-eval` semantics for impure builtins and path access.
    Pure,
}

/// Evaluator settings that must be shared by native and C++ Nix evaluators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NixEvalConfig {
    eval_mode: NixEvalMode,
    allowed_paths: Vec<String>,
    allowed_uris: Vec<String>,
    eval_env_vars: BTreeMap<Vec<u8>, Vec<u8>>,
    nix_path: Option<String>,
    current_system: Option<String>,
    store_dir: Option<String>,
    state_dir: Option<String>,
    log_dir: Option<String>,
    working_dir: Option<PathBuf>,
    home_dir: Option<PathBuf>,
    native_cache_root: Option<PathBuf>,
    native_cache_verify: bool,
    native_root_cutoff: bool,
    native_root_cutoff_check: bool,
    native_eval_stats: bool,
    native_jit: bool,
    native_parallel_workers: Option<std::num::NonZeroUsize>,
    native_memo: NativeMemoSettings,
    native_memo_disk_spec: Option<String>,
    native_memo_net: Option<NativeMemoNetSettings>,
    heap_memory_budget_bytes: Option<usize>,
    trace_verbose: bool,
}

/// Parsed `AOS_NIX_MEMO*` settings for the native content-keyed memo tiers.
///
/// Mirrors the native evaluator's `MemoOptions` with plain types so the
/// configuration exists independently of the `native-eval` feature. All
/// fields are advisory performance settings; none affect evaluation results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeMemoSettings {
    /// Master switch (`AOS_NIX_MEMO`). Off by default in this landing.
    pub enabled: bool,
    /// Per-worker in-thread tier switch (`AOS_NIX_MEMO_L0`).
    pub l0_enabled: bool,
    /// In-process shared tier switch (`AOS_NIX_MEMO_L1`); `None` selects the
    /// default policy (on exactly when parallel workers are configured).
    pub l1_enabled: Option<bool>,
    /// Static recompute-estimate admission floor (`AOS_NIX_MEMO_MIN_COST`).
    pub min_cost: u32,
    /// Per-worker L0 entry cap (`AOS_NIX_MEMO_L0_ENTRIES`).
    pub l0_entries: usize,
    /// L1 retained-bytes budget (`AOS_NIX_MEMO_L1_BYTES`).
    pub l1_bytes: u64,
    /// Hits at L1 before an entry also installs at L0
    /// (`AOS_NIX_MEMO_PROMOTE_HITS`).
    pub promote_hits: u32,
    /// Shadow-check every L0 hit (`AOS_NIX_MEMO_CHECK` contains `l0`/`all`).
    pub check_l0: bool,
    /// Shadow-check every L1 hit (`AOS_NIX_MEMO_CHECK` contains `l1`/`all`).
    pub check_l1: bool,
    /// Secondary L2 disk-location kill switch (`AOS_NIX_MEMO_L2`, default on).
    ///
    /// Governs only the additive `AOS_NIX_MEMO_DISK` secondaries; the primary
    /// `AOS_NIX_CACHE` location keeps its own existing switches.
    pub l2_enabled: bool,
    /// Shadow-check every secondary-location root-cutoff hit
    /// (`AOS_NIX_MEMO_CHECK` contains `l2`/`all`).
    pub check_l2: bool,
    /// Shadow-check every network-tier root-cutoff hit
    /// (`AOS_NIX_MEMO_CHECK` contains `l3`/`all`).
    pub check_l3: bool,
}

impl Default for NativeMemoSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            l0_enabled: true,
            l1_enabled: None,
            min_cost: 64,
            l0_entries: 65_536,
            l1_bytes: 256 * 1024 * 1024,
            promote_hits: 2,
            check_l0: false,
            check_l1: false,
            l2_enabled: true,
            check_l2: false,
            check_l3: false,
        }
    }
}

/// Parsed `AOS_NIX_MEMO_NET*` settings for the L3 network memo tier.
///
/// Mirrors the native evaluator's `MemoNetOptions` with plain types so the
/// configuration exists independently of the `native-eval` feature. The tier
/// is advisory and read-only by default; it only takes effect alongside a
/// configured `AOS_NIX_CACHE` root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeMemoNetSettings {
    /// Base endpoint URL (`AOS_NIX_MEMO_NET`).
    pub endpoint: String,
    /// Whether publishing is allowed (`AOS_NIX_MEMO_NET_MODE=rw`).
    pub writable: bool,
    /// Per-request timeout in milliseconds (`AOS_NIX_MEMO_NET_TIMEOUT_MS`).
    pub timeout_ms: u64,
}

/// The default L3 network-tier request timeout in milliseconds.
const NATIVE_MEMO_NET_DEFAULT_TIMEOUT_MS: u64 = 2_000;

impl Default for NixEvalConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl NixEvalConfig {
    /// Creates evaluator settings using C++ Nix's ambient defaults.
    ///
    /// Store, state, and log directories are captured from `AOS_ROOT`-derived
    /// settings or inherited `NIX_*` environment variables so native evaluation
    /// targets the same store directory as real Nix subprocesses.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates evaluator settings with a configured Nix `system` value.
    ///
    /// The value is passed to C++ Nix as `--option system <value>` and to the
    /// native evaluator as `builtins.currentSystem`.
    ///
    /// # Errors
    ///
    /// Returns an error if `current_system` is empty.
    pub fn with_current_system(current_system: impl Into<String>) -> Result<Self> {
        let mut config = Self::default();
        config.set_current_system(current_system)?;
        Ok(config)
    }

    /// Creates evaluator settings with configured Nix store directories.
    ///
    /// The store directory is passed to the native evaluator and the full
    /// store/state/log triple is passed to C++ Nix subprocesses through their
    /// corresponding `NIX_*` environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error if any directory is empty or relative.
    pub fn with_store_dirs(
        store_dir: impl Into<String>,
        state_dir: impl Into<String>,
        log_dir: impl Into<String>,
    ) -> Result<Self> {
        let mut config = Self::default();
        config.set_store_dirs(store_dir, state_dir, log_dir)?;
        Ok(config)
    }

    /// Returns the configured evaluation impurity mode.
    pub const fn eval_mode(&self) -> NixEvalMode {
        self.eval_mode
    }

    /// Returns filesystem roots allowed during restricted evaluation.
    pub fn allowed_paths(&self) -> &[String] {
        &self.allowed_paths
    }

    /// Returns URI prefixes allowed during restricted evaluation.
    pub fn allowed_uris(&self) -> &[String] {
        &self.allowed_uris
    }

    /// Returns the configured `NIX_PATH` environment value, if one was provided.
    pub fn nix_path_env(&self) -> Option<&str> {
        self.nix_path.as_deref()
    }

    /// Returns the configured Nix `system` value, if one was provided.
    pub fn current_system(&self) -> Option<&str> {
        self.current_system.as_deref()
    }

    /// Returns the configured Nix store directory, if one was provided.
    pub fn store_dir(&self) -> Option<&str> {
        self.store_dir.as_deref()
    }

    /// Returns the configured Nix state directory, if one was provided.
    pub fn state_dir(&self) -> Option<&str> {
        self.state_dir.as_deref()
    }

    /// Returns the configured Nix log directory, if one was provided.
    pub fn log_dir(&self) -> Option<&str> {
        self.log_dir.as_deref()
    }

    /// Returns evaluator environment variables applied to C++ Nix subprocesses.
    pub fn eval_env_vars(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.eval_env_vars
            .iter()
            .map(|(name, value)| (name.as_slice(), value.as_slice()))
    }

    /// Returns the evaluator working directory, if one was provided.
    ///
    /// C++ Nix uses this as the subprocess current directory. Native
    /// evaluation uses it as the base for relative expression path literals
    /// and relative search-path entries.
    pub fn working_dir(&self) -> Option<&Path> {
        self.working_dir.as_deref()
    }

    /// Returns the configured home directory, if one was provided.
    pub fn home_dir(&self) -> Option<&Path> {
        self.home_dir.as_deref()
    }

    /// Returns the native evaluator cache root, if one was provided.
    ///
    /// The parse cache stores entries below this root's `parse/` child, and
    /// file-derived persistent artifacts use its `persist/` child. The
    /// in-memory incremental eval-cache precursor also uses this setting as
    /// its enable switch, but it does not persist demand-graph records yet.
    pub fn native_cache_root(&self) -> Option<&Path> {
        self.native_cache_root.as_deref()
    }

    /// Returns whether native persistent value-decode re-hashing is enabled.
    ///
    /// This defensive check is off by default and enabled through the
    /// `AOS_NIX_CACHE_VERIFY` environment variable. When off, indexed value
    /// decoding trusts the content-addressed pack and its integrity headers.
    pub const fn native_cache_verify(&self) -> bool {
        self.native_cache_verify
    }

    /// Enables or disables native persistent value-decode content re-hashing.
    pub fn set_native_cache_verify(&mut self, native_cache_verify: bool) {
        self.native_cache_verify = native_cache_verify;
    }

    /// Returns whether the native tier-1 JIT engine is enabled.
    ///
    /// Off by default and enabled through the `AOS_NIX_JIT=1` environment
    /// variable. When on, the native evaluator promotes hot thunk bodies to
    /// Cranelift tier-1 code and dispatches it, deoptimizing to the tree walk on
    /// any trap so results are unchanged.
    pub const fn native_jit(&self) -> bool {
        self.native_jit
    }

    /// Enables or disables the native tier-1 JIT engine.
    pub fn set_native_jit(&mut self, native_jit: bool) {
        self.native_jit = native_jit;
    }

    /// Returns the native parallel evaluation worker count, if enabled.
    ///
    /// Off by default and enabled through the `AOS_NIX_PARALLEL=<n>`
    /// environment variable. When set, native evaluation runs in parallel
    /// mode: thunks carry parallel claim/park cells bound to a shared
    /// cross-worker wait registry. The count records the requested fan-out for
    /// scheduler integration; evaluation results are unchanged. Parallel mode
    /// ignores `AOS_NIX_JIT` (the tier-1 engine is worker-affine).
    pub const fn native_parallel_workers(&self) -> Option<std::num::NonZeroUsize> {
        self.native_parallel_workers
    }

    /// Enables or disables native parallel evaluation mode.
    /// Returns the native content-memo settings.
    pub const fn native_memo(&self) -> NativeMemoSettings {
        self.native_memo
    }

    /// Replaces the native content-memo settings.
    pub fn set_native_memo(&mut self, memo: NativeMemoSettings) {
        self.native_memo = memo;
    }

    /// Returns the raw secondary L2 disk-location spec (`AOS_NIX_MEMO_DISK`).
    ///
    /// The spec grammar (`class:path[,class:path...]`) is parsed by the native
    /// evaluator when options are built; an invalid spec disables the
    /// secondaries with a warning rather than failing evaluation.
    pub fn native_memo_disk_spec(&self) -> Option<&str> {
        self.native_memo_disk_spec.as_deref()
    }

    /// Replaces the raw secondary L2 disk-location spec.
    pub fn set_native_memo_disk_spec(&mut self, spec: Option<String>) {
        self.native_memo_disk_spec = spec;
    }

    /// Returns the L3 network memo-tier settings, if configured.
    pub fn native_memo_net(&self) -> Option<&NativeMemoNetSettings> {
        self.native_memo_net.as_ref()
    }

    /// Replaces the L3 network memo-tier settings.
    pub fn set_native_memo_net(&mut self, net: Option<NativeMemoNetSettings>) {
        self.native_memo_net = net;
    }

    pub fn set_native_parallel_workers(&mut self, workers: Option<std::num::NonZeroUsize>) {
        self.native_parallel_workers = workers;
    }

    /// Returns whether native root-level early cutoff is enabled.
    ///
    /// Root cutoff is on by default and answers a fully warm
    /// `instantiate(file, attr)` from a durable record, skipping evaluation. It
    /// only takes effect when a native cache root is configured, and is disabled
    /// through the `AOS_NIX_ROOT_CUTOFF=0` kill switch.
    pub const fn native_root_cutoff(&self) -> bool {
        self.native_root_cutoff
    }

    /// Enables or disables native root-level early cutoff.
    pub fn set_native_root_cutoff(&mut self, native_root_cutoff: bool) {
        self.native_root_cutoff = native_root_cutoff;
    }

    /// Returns whether native root-cutoff cross-check mode is enabled.
    ///
    /// When enabled, a taken cutoff also runs the full evaluation and asserts a
    /// byte-identical closure, reporting divergence loudly. This is a hardening
    /// aid enabled through `AOS_NIX_ROOT_CUTOFF_CHECK=1`.
    pub const fn native_root_cutoff_check(&self) -> bool {
        self.native_root_cutoff_check
    }

    /// Enables or disables native root-cutoff cross-check mode.
    pub fn set_native_root_cutoff_check(&mut self, native_root_cutoff_check: bool) {
        self.native_root_cutoff_check = native_root_cutoff_check;
    }

    /// Returns whether native evaluation work-volume statistics dumping is enabled.
    ///
    /// Off by default and enabled through the `AOS_NIX_EVAL_STATS=1` environment
    /// variable. When on, the native instantiate path prints the evaluator's
    /// work counters as a single JSON object to stderr at the end of an
    /// evaluation, for comparison against C++ Nix's `NIX_SHOW_STATS`.
    pub const fn native_eval_stats(&self) -> bool {
        self.native_eval_stats
    }

    /// Enables or disables native evaluation work-volume statistics dumping.
    pub fn set_native_eval_stats(&mut self, native_eval_stats: bool) {
        self.native_eval_stats = native_eval_stats;
    }

    /// Returns the configured native heap high-water budget in bytes, if set.
    pub const fn heap_memory_budget_bytes(&self) -> Option<usize> {
        self.heap_memory_budget_bytes
    }

    /// Returns whether `builtins.traceVerbose` should emit trace output.
    pub const fn trace_verbose(&self) -> bool {
        self.trace_verbose
    }

    /// Returns C++ Nix CLI options that reproduce these evaluator settings.
    pub(crate) fn cli_option_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(current_system) = self.current_system() {
            push_cli_option(&mut args, "system", current_system);
        }
        if self.eval_mode != NixEvalMode::Ambient {
            push_cli_option(
                &mut args,
                "pure-eval",
                match self.eval_mode {
                    NixEvalMode::Pure => "true",
                    NixEvalMode::Ambient | NixEvalMode::Impure | NixEvalMode::Restricted => "false",
                },
            );
            push_cli_option(
                &mut args,
                "restrict-eval",
                match self.eval_mode {
                    NixEvalMode::Restricted => "true",
                    NixEvalMode::Ambient | NixEvalMode::Impure | NixEvalMode::Pure => "false",
                },
            );
        }
        if self.eval_mode == NixEvalMode::Restricted {
            push_cli_option(
                &mut args,
                "allowed-impure-host-deps",
                self.allowed_paths.join(" "),
            );
            push_cli_option(&mut args, "allowed-uris", self.allowed_uris.join(" "));
        }
        if self.trace_verbose {
            push_cli_option(&mut args, "trace-verbose", "true");
        }
        args
    }

    pub(crate) fn cli_search_path_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if self.eval_mode == NixEvalMode::Restricted {
            for path in &self.allowed_paths {
                args.push("-I".to_string());
                args.push(path.clone());
            }
        }
        args
    }

    /// Returns C++ Nix environment bindings that reproduce these settings.
    pub(crate) fn cli_env_vars(&self) -> Vec<(&'static str, String)> {
        let mut vars = Vec::new();
        if let Some(store_dir) = &self.store_dir {
            vars.push(("NIX_STORE_DIR", store_dir.clone()));
        }
        if let Some(state_dir) = &self.state_dir {
            vars.push(("NIX_STATE_DIR", state_dir.clone()));
        }
        if let Some(log_dir) = &self.log_dir {
            vars.push(("NIX_LOG_DIR", log_dir.clone()));
        }
        if let Some(nix_path) = &self.nix_path {
            vars.push(("NIX_PATH", nix_path.clone()));
        }
        vars
    }

    /// Applies C++ Nix environment bindings to a command.
    pub(crate) fn apply_cli_env(&self, command: &mut Command) {
        command.env_clear();
        for (name, value) in &self.eval_env_vars {
            command.env(
                os_string_from_env_bytes(name.clone()),
                os_string_from_env_bytes(value.clone()),
            );
        }
        for (name, value) in self.cli_env_vars() {
            command.env(name, value);
        }
        command.env_remove("AOS_NIX_NATIVE");
        command.env_remove("AOS_NIX_NATIVE_VERIFY");
        if let Some(working_dir) = self.working_dir() {
            command.current_dir(working_dir);
        }
    }

    /// Replaces the configured evaluation impurity mode.
    pub fn set_eval_mode(&mut self, eval_mode: NixEvalMode) {
        self.eval_mode = eval_mode;
    }

    /// Adds a filesystem root allowed during restricted evaluation.
    ///
    /// # Errors
    ///
    /// Returns an error if `path` is empty or relative.
    pub fn add_allowed_path(&mut self, path: impl Into<String>) -> Result<()> {
        let path = validate_allowed_eval_path(path.into())?;
        self.allowed_paths.push(path);
        Ok(())
    }

    /// Replaces filesystem roots allowed during restricted evaluation.
    ///
    /// # Errors
    ///
    /// Returns an error if any path is empty or relative.
    pub fn set_allowed_paths<I, P>(&mut self, paths: I) -> Result<()>
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        let mut allowed_paths = Vec::new();
        for path in paths {
            allowed_paths.push(validate_allowed_eval_path(path.into())?);
        }
        self.allowed_paths = allowed_paths;
        Ok(())
    }

    /// Clears all restricted-evaluation filesystem roots.
    pub fn clear_allowed_paths(&mut self) {
        self.allowed_paths.clear();
    }

    /// Adds a URI prefix allowed during restricted evaluation.
    ///
    /// # Errors
    ///
    /// Returns an error if `uri` is empty.
    pub fn add_allowed_uri(&mut self, uri: impl Into<String>) -> Result<()> {
        let uri = validate_allowed_uri(uri.into())?;
        self.allowed_uris.push(uri);
        Ok(())
    }

    /// Replaces URI prefixes allowed during restricted evaluation.
    ///
    /// # Errors
    ///
    /// Returns an error if any URI prefix is empty.
    pub fn set_allowed_uris<I, U>(&mut self, uris: I) -> Result<()>
    where
        I: IntoIterator<Item = U>,
        U: Into<String>,
    {
        let mut allowed_uris = Vec::new();
        for uri in uris {
            allowed_uris.push(validate_allowed_uri(uri.into())?);
        }
        self.allowed_uris = allowed_uris;
        Ok(())
    }

    /// Clears all restricted-evaluation URI prefixes.
    pub fn clear_allowed_uris(&mut self) {
        self.allowed_uris.clear();
    }

    /// Replaces the configured `NIX_PATH` environment value.
    ///
    /// The value uses C++ Nix's legacy environment format. Native evaluation
    /// maps filesystem-style entries and falls back to C++ Nix for URL,
    /// channel, and flake-style entries it cannot represent faithfully.
    pub fn set_nix_path_env(&mut self, nix_path: impl Into<String>) {
        self.set_cli_env_var("NIX_PATH", nix_path.into());
    }

    /// Clears the configured `NIX_PATH` environment value.
    pub fn clear_nix_path_env(&mut self) {
        self.nix_path = None;
        self.clear_eval_env_var(b"NIX_PATH");
    }

    /// Replaces the configured Nix `system` value.
    ///
    /// # Errors
    ///
    /// Returns an error if `current_system` is empty.
    pub fn set_current_system(&mut self, current_system: impl Into<String>) -> Result<()> {
        let current_system = current_system.into();
        if current_system.is_empty() {
            anyhow::bail!("Nix currentSystem value must not be empty");
        }
        self.current_system = Some(current_system);
        Ok(())
    }

    /// Clears the configured Nix `system` value.
    pub fn clear_current_system(&mut self) {
        self.current_system = None;
    }

    /// Replaces the configured Nix store, state, and log directories.
    ///
    /// # Errors
    ///
    /// Returns an error if any directory is empty or relative.
    pub fn set_store_dirs(
        &mut self,
        store_dir: impl Into<String>,
        state_dir: impl Into<String>,
        log_dir: impl Into<String>,
    ) -> Result<()> {
        let store_dir = validate_absolute_env_path("NIX_STORE_DIR", store_dir.into())?;
        let state_dir = validate_absolute_env_path("NIX_STATE_DIR", state_dir.into())?;
        let log_dir = validate_absolute_env_path("NIX_LOG_DIR", log_dir.into())?;
        self.set_cli_env_var("NIX_STORE_DIR", store_dir);
        self.set_cli_env_var("NIX_STATE_DIR", state_dir);
        self.set_cli_env_var("NIX_LOG_DIR", log_dir);
        Ok(())
    }

    /// Clears configured Nix store, state, and log directories.
    pub fn clear_store_dirs(&mut self) {
        self.store_dir = None;
        self.state_dir = None;
        self.log_dir = None;
        self.clear_eval_env_var(b"NIX_STORE_DIR");
        self.clear_eval_env_var(b"NIX_STATE_DIR");
        self.clear_eval_env_var(b"NIX_LOG_DIR");
    }

    /// Replaces the evaluator working directory.
    ///
    /// Relative paths are resolved against the process current directory when
    /// this method is called, matching how a subprocess would interpret a
    /// relative `current_dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if `working_dir` is empty, cannot be made absolute, or
    /// does not name an existing directory.
    pub fn set_working_dir(&mut self, working_dir: impl Into<PathBuf>) -> Result<()> {
        let working_dir =
            absolutize_config_path("evaluator working directory", working_dir.into())?;
        if !working_dir.is_dir() {
            anyhow::bail!(
                "evaluator working directory must be an existing directory: {}",
                working_dir.display()
            );
        }
        self.working_dir = Some(working_dir);
        Ok(())
    }

    /// Clears the evaluator working directory.
    pub fn clear_working_dir(&mut self) {
        self.working_dir = None;
    }

    /// Replaces the configured home directory.
    ///
    /// This also updates the `HOME` binding seen by C++ Nix subprocesses and
    /// by native `builtins.getEnv`.
    ///
    /// # Errors
    ///
    /// Returns an error if `home_dir` is empty or relative.
    pub fn set_home_dir(&mut self, home_dir: impl Into<PathBuf>) -> Result<()> {
        let home_dir = validate_absolute_config_path("HOME", home_dir.into())?;
        self.set_eval_env_var_bytes(b"HOME".to_vec(), path_bytes(&home_dir));
        self.home_dir = Some(home_dir);
        Ok(())
    }

    /// Clears the configured home directory and the corresponding `HOME` binding.
    pub fn clear_home_dir(&mut self) {
        self.home_dir = None;
        self.clear_eval_env_var(b"HOME");
    }

    /// Replaces the native evaluator cache root.
    ///
    /// The parse cache stores entries below this root's `parse/` child, and
    /// file-derived persistent artifacts use its `persist/` child. The
    /// in-memory incremental eval-cache precursor also uses this setting as
    /// its enable switch. Use [`Self::clear_native_cache_root`] for uncached
    /// native evaluation.
    ///
    /// # Errors
    ///
    /// Returns an error if `native_cache_root` is empty or relative.
    pub fn set_native_cache_root(&mut self, native_cache_root: impl Into<PathBuf>) -> Result<()> {
        self.native_cache_root = Some(validate_absolute_config_path(
            "AOS_NIX_CACHE",
            native_cache_root.into(),
        )?);
        Ok(())
    }

    /// Clears the native evaluator cache root.
    pub fn clear_native_cache_root(&mut self) {
        self.native_cache_root = None;
    }

    /// Replaces the native heap high-water budget in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `max_resident_bytes` is zero.
    pub fn set_heap_memory_budget_bytes(&mut self, max_resident_bytes: usize) -> Result<()> {
        if max_resident_bytes == 0 {
            anyhow::bail!("native heap memory budget must be greater than zero bytes");
        }
        self.heap_memory_budget_bytes = Some(max_resident_bytes);
        Ok(())
    }

    /// Clears the native heap high-water budget.
    pub fn clear_heap_memory_budget(&mut self) {
        self.heap_memory_budget_bytes = None;
    }

    /// Configures whether `builtins.traceVerbose` should emit trace output.
    pub fn set_trace_verbose(&mut self, trace_verbose: bool) {
        self.trace_verbose = trace_verbose;
    }

    fn from_env() -> Self {
        let mut config = Self {
            eval_mode: NixEvalMode::Ambient,
            allowed_paths: Vec::new(),
            allowed_uris: Vec::new(),
            eval_env_vars: eval_env_vars_from_process(),
            nix_path: None,
            current_system: None,
            store_dir: None,
            state_dir: None,
            log_dir: None,
            working_dir: None,
            home_dir: None,
            native_cache_root: None,
            native_cache_verify: false,
            native_root_cutoff: true,
            native_root_cutoff_check: false,
            native_eval_stats: false,
            native_jit: false,
            native_parallel_workers: None,
            native_memo: NativeMemoSettings::default(),
            native_memo_disk_spec: None,
            native_memo_net: None,
            heap_memory_budget_bytes: None,
            trace_verbose: false,
        };

        let mut env = aos_nix_env();
        if env.is_empty() {
            env.extend(nix_env_from_process("NIX_STORE_DIR"));
            env.extend(nix_env_from_process("NIX_STATE_DIR"));
            env.extend(nix_env_from_process("NIX_LOG_DIR"));
        }
        for (name, value) in env {
            config.set_cli_env_var(name, value);
        }
        if let Ok(value) = std::env::var("NIX_PATH") {
            config.set_cli_env_var("NIX_PATH", value);
        }
        if let Ok(value) = std::env::var("AOS_NIX_CACHE") {
            config.set_aos_nix_cache_env_var(value);
        }
        if let Ok(value) = std::env::var("AOS_NIX_CACHE_VERIFY") {
            config.set_aos_nix_cache_verify_env_var(&value);
        }
        if let Ok(value) = std::env::var("AOS_NIX_ROOT_CUTOFF") {
            config.set_aos_nix_root_cutoff_env_var(&value);
        }
        if let Ok(value) = std::env::var("AOS_NIX_ROOT_CUTOFF_CHECK") {
            config.set_aos_nix_root_cutoff_check_env_var(&value);
        }
        if let Ok(value) = std::env::var("AOS_NIX_EVAL_STATS") {
            config.set_aos_nix_eval_stats_env_var(&value);
        }
        if let Ok(value) = std::env::var("AOS_NIX_JIT") {
            config.set_aos_nix_jit_env_var(&value);
        }
        if let Ok(value) = std::env::var("AOS_NIX_PARALLEL") {
            config.set_aos_nix_parallel_env_var(&value);
        }
        if let Ok(value) = std::env::var("AOS_NIX_MAX_RSS") {
            config.set_aos_nix_max_rss_env_var(value);
        }
        config.set_aos_nix_memo_env_vars(EnvMemoKnobs::from_process());
        match std::env::current_dir() {
            Ok(working_dir) => config.working_dir = Some(working_dir),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "unable to capture evaluator working directory; relative native path context disabled"
                );
            }
        }
        config.set_home_dir_from_env_snapshot();

        config
    }

    fn set_aos_nix_cache_env_var(&mut self, value: String) {
        let Some(root) = native_cache_root_from_env_value(&value) else {
            self.clear_native_cache_root();
            return;
        };
        if let Err(error) = self.set_native_cache_root(root) {
            tracing::warn!(
                error = %error,
                value,
                "invalid AOS_NIX_CACHE value; disabling native evaluator cache"
            );
            self.clear_native_cache_root();
        }
    }

    fn set_aos_nix_cache_verify_env_var(&mut self, value: &str) {
        self.set_native_cache_verify(matches!(value.trim(), "1" | "true"));
    }

    fn set_aos_nix_jit_env_var(&mut self, value: &str) {
        self.set_native_jit(matches!(value.trim(), "1" | "true"));
    }

    fn set_aos_nix_parallel_env_var(&mut self, value: &str) {
        let trimmed = value.trim();
        if matches!(trimmed, "" | "0" | "false" | "off" | "no") {
            self.set_native_parallel_workers(None);
            return;
        }
        match trimmed.parse::<std::num::NonZeroUsize>() {
            Ok(workers) => {
                if self.native_jit() {
                    tracing::warn!(
                        workers = workers.get(),
                        "AOS_NIX_JIT is ignored under AOS_NIX_PARALLEL; the tier-1 engine is worker-affine"
                    );
                }
                self.set_native_parallel_workers(Some(workers));
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    value,
                    "invalid AOS_NIX_PARALLEL value; disabling native parallel evaluation"
                );
                self.set_native_parallel_workers(None);
            }
        }
    }

    fn set_aos_nix_root_cutoff_env_var(&mut self, value: &str) {
        // Root cutoff is on by default; this is a kill switch, so only explicit
        // falsy values disable it and anything else leaves it enabled.
        self.set_native_root_cutoff(!matches!(value.trim(), "0" | "false" | "off" | "no"));
    }

    fn set_aos_nix_root_cutoff_check_env_var(&mut self, value: &str) {
        self.set_native_root_cutoff_check(matches!(value.trim(), "1" | "true"));
    }

    fn set_aos_nix_eval_stats_env_var(&mut self, value: &str) {
        self.set_native_eval_stats(matches!(value.trim(), "1" | "true"));
    }

    /// Applies one snapshot of the `AOS_NIX_MEMO*` environment knobs.
    ///
    /// Boolean knobs parse like the existing switches (`0`/`false`/`off`/`no`
    /// disable); numeric knobs fall back to their defaults with a warning on
    /// invalid values — the memo store is advisory, so configuration errors
    /// never fail evaluation.
    fn set_aos_nix_memo_env_vars(&mut self, knobs: EnvMemoKnobs) {
        let mut memo = self.native_memo;
        if let Some(value) = knobs.master.as_deref() {
            memo.enabled = env_flag_is_truthy(value);
        }
        if let Some(value) = knobs.l0.as_deref() {
            memo.l0_enabled = !env_flag_is_falsy(value);
        }
        if let Some(value) = knobs.l1.as_deref() {
            let trimmed = value.trim();
            memo.l1_enabled = if trimmed.is_empty() {
                None
            } else if env_flag_is_falsy(trimmed) {
                Some(false)
            } else {
                Some(true)
            };
        }
        if let Some(value) = knobs.min_cost.as_deref() {
            match value.trim().parse::<u32>() {
                Ok(min_cost) => memo.min_cost = min_cost,
                Err(error) => tracing::warn!(
                    error = %error,
                    value,
                    "invalid AOS_NIX_MEMO_MIN_COST value; keeping the default admission floor"
                ),
            }
        }
        if let Some(value) = knobs.l0_entries.as_deref() {
            match value.trim().parse::<usize>() {
                Ok(entries) => memo.l0_entries = entries,
                Err(error) => tracing::warn!(
                    error = %error,
                    value,
                    "invalid AOS_NIX_MEMO_L0_ENTRIES value; keeping the default entry cap"
                ),
            }
        }
        if let Some(value) = knobs.l1_bytes.as_deref() {
            match value.trim().parse::<u64>() {
                Ok(bytes) => memo.l1_bytes = bytes,
                Err(error) => tracing::warn!(
                    error = %error,
                    value,
                    "invalid AOS_NIX_MEMO_L1_BYTES value; keeping the default byte budget"
                ),
            }
        }
        if let Some(value) = knobs.promote_hits.as_deref() {
            match value.trim().parse::<u32>() {
                Ok(hits) => memo.promote_hits = hits,
                Err(error) => tracing::warn!(
                    error = %error,
                    value,
                    "invalid AOS_NIX_MEMO_PROMOTE_HITS value; keeping the default threshold"
                ),
            }
        }
        if let Some(value) = knobs.l2.as_deref() {
            memo.l2_enabled = !env_flag_is_falsy(value);
        }
        if let Some(value) = knobs.check.as_deref() {
            memo.check_l0 = false;
            memo.check_l1 = false;
            memo.check_l2 = false;
            memo.check_l3 = false;
            for tier in value.split(',') {
                match tier.trim().to_ascii_lowercase().as_str() {
                    "" => {}
                    "all" => {
                        memo.check_l0 = true;
                        memo.check_l1 = true;
                        memo.check_l2 = true;
                        memo.check_l3 = true;
                    }
                    "l0" => memo.check_l0 = true,
                    "l1" => memo.check_l1 = true,
                    "l2" => memo.check_l2 = true,
                    "l3" => memo.check_l3 = true,
                    other => tracing::warn!(
                        tier = other,
                        "unknown AOS_NIX_MEMO_CHECK tier; ignoring it"
                    ),
                }
            }
        }
        self.native_memo = memo;
        if let Some(value) = knobs.disk {
            let trimmed = value.trim();
            self.native_memo_disk_spec = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        if let Some(value) = knobs.net {
            let endpoint = value.trim().trim_end_matches('/').to_string();
            self.native_memo_net = if endpoint.is_empty() {
                None
            } else {
                let writable = match knobs.net_mode.as_deref().map(str::trim) {
                    None | Some("") | Some("ro") => false,
                    Some("rw") => true,
                    Some(other) => {
                        tracing::warn!(
                            mode = other,
                            "unknown AOS_NIX_MEMO_NET_MODE value; staying read-only"
                        );
                        false
                    }
                };
                let timeout_ms = match knobs.net_timeout_ms.as_deref().map(str::trim) {
                    None | Some("") => NATIVE_MEMO_NET_DEFAULT_TIMEOUT_MS,
                    Some(raw) => match raw.parse::<u64>() {
                        Ok(timeout_ms) => timeout_ms,
                        Err(error) => {
                            tracing::warn!(
                                error = %error,
                                value = raw,
                                "invalid AOS_NIX_MEMO_NET_TIMEOUT_MS value; keeping the default"
                            );
                            NATIVE_MEMO_NET_DEFAULT_TIMEOUT_MS
                        }
                    },
                };
                Some(NativeMemoNetSettings {
                    endpoint,
                    writable,
                    timeout_ms,
                })
            };
        }
    }

    fn set_aos_nix_max_rss_env_var(&mut self, value: String) {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            self.clear_heap_memory_budget();
            return;
        }
        match trimmed.parse::<usize>() {
            Ok(bytes) => {
                if let Err(error) = self.set_heap_memory_budget_bytes(bytes) {
                    tracing::warn!(
                        error = %error,
                        value,
                        "invalid AOS_NIX_MAX_RSS value; disabling native heap memory budget"
                    );
                    self.clear_heap_memory_budget();
                }
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    value,
                    "invalid AOS_NIX_MAX_RSS value; disabling native heap memory budget"
                );
                self.clear_heap_memory_budget();
            }
        }
    }

    fn set_cli_env_var(&mut self, name: &'static str, value: String) {
        self.set_eval_env_var_bytes(name.as_bytes().to_vec(), value.as_bytes().to_vec());
        match name {
            "NIX_STORE_DIR" => self.store_dir = Some(value),
            "NIX_STATE_DIR" => self.state_dir = Some(value),
            "NIX_LOG_DIR" => self.log_dir = Some(value),
            "NIX_PATH" => self.nix_path = Some(value),
            "HOME" => self.set_home_dir_from_env_snapshot(),
            _ => {}
        }
    }

    fn set_eval_env_var_bytes(&mut self, name: Vec<u8>, value: Vec<u8>) {
        if !is_evaluator_control_env_var(&name) {
            self.eval_env_vars.insert(name, value);
        }
    }

    fn clear_eval_env_var(&mut self, name: &[u8]) {
        self.eval_env_vars.remove(name);
    }

    pub(crate) fn resolve_eval_file_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else if let Some(working_dir) = self.working_dir() {
            working_dir.join(path)
        } else {
            path.to_path_buf()
        }
    }

    fn set_home_dir_from_env_snapshot(&mut self) {
        let Some(value) = self.eval_env_vars.get(b"HOME".as_slice()) else {
            self.home_dir = None;
            return;
        };
        let home_dir = PathBuf::from(os_string_from_env_bytes(value.clone()));
        match validate_absolute_config_path("HOME", home_dir) {
            Ok(home_dir) => self.home_dir = Some(home_dir),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "invalid HOME value; native home path expansion disabled"
                );
                self.home_dir = None;
            }
        }
    }
}

#[cfg(any(test, feature = "native-eval"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct NixPathConfigEntry {
    prefix: String,
    path: String,
}

fn push_cli_option(args: &mut Vec<String>, name: &str, value: impl Into<String>) {
    args.extend(["--option".to_string(), name.to_string(), value.into()]);
}

#[cfg(any(test, feature = "native-eval"))]
fn native_nix_path_entries_from_env_value(value: &str) -> Option<Vec<NixPathConfigEntry>> {
    if value.is_empty() || nix_path_contains_native_unsupported_entry(value) {
        return None;
    }

    let entries = value
        .split(':')
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (prefix, path) = entry.split_once('=').unwrap_or(("", entry));
            NixPathConfigEntry {
                prefix: prefix.to_string(),
                path: path.to_string(),
            }
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

#[cfg(any(test, feature = "native-eval"))]
fn nix_path_contains_native_unsupported_entry(value: &str) -> bool {
    value.contains("://")
        || value.contains("channel:")
        || value.contains("flake:")
        || value.contains("github:")
        || value.contains("gitlab:")
        || value.contains("sourcehut:")
}

fn native_cache_root_from_env_value(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "0" {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn nix_env_from_process(name: &'static str) -> Option<(&'static str, String)> {
    std::env::var(name).ok().map(|value| (name, value))
}

fn absolutize_config_path(name: &str, value: PathBuf) -> Result<PathBuf> {
    if value.as_os_str().is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    if value.is_absolute() {
        return Ok(value);
    }
    let cwd = std::env::current_dir().map_err(|source| {
        anyhow::anyhow!("cannot resolve {name} against current directory: {source}")
    })?;
    Ok(cwd.join(value))
}

fn eval_env_vars_from_process() -> BTreeMap<Vec<u8>, Vec<u8>> {
    std::env::vars_os()
        .filter_map(|(name, value)| {
            let name = env_bytes_from_os_string(name);
            if is_evaluator_control_env_var(&name) {
                None
            } else {
                Some((name, env_bytes_from_os_string(value)))
            }
        })
        .collect()
}

fn is_evaluator_control_env_var(name: &[u8]) -> bool {
    matches!(
        name,
        b"AOS_NIX_NATIVE" | b"AOS_NIX_NATIVE_VERIFY" | b"AOS_NIX_MAX_RSS"
    )
}

#[cfg(unix)]
fn env_bytes_from_os_string(value: OsString) -> Vec<u8> {
    value.into_vec()
}

#[cfg(not(unix))]
fn env_bytes_from_os_string(value: OsString) -> Vec<u8> {
    value.to_string_lossy().into_owned().into_bytes()
}

#[cfg(unix)]
fn os_string_from_env_bytes(value: Vec<u8>) -> OsString {
    OsString::from_vec(value)
}

#[cfg(not(unix))]
fn os_string_from_env_bytes(value: Vec<u8>) -> OsString {
    OsString::from(String::from_utf8_lossy(&value).into_owned())
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().into_owned().into_bytes()
}

fn validate_absolute_config_path(name: &str, value: PathBuf) -> Result<PathBuf> {
    if value.as_os_str().is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    if !value.is_absolute() {
        anyhow::bail!("{name} must be absolute: {}", value.display());
    }
    Ok(value)
}

fn validate_absolute_env_path(name: &str, value: String) -> Result<String> {
    if value.is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    if !Path::new(&value).is_absolute() {
        anyhow::bail!("{name} must be absolute: {value}");
    }
    Ok(value)
}

fn validate_allowed_eval_path(value: String) -> Result<String> {
    let value = validate_absolute_env_path("allowed evaluation path", value)?;
    if value.chars().any(char::is_whitespace) {
        anyhow::bail!("allowed evaluation path must not contain whitespace: {value}");
    }
    Ok(value)
}

fn validate_allowed_uri(value: String) -> Result<String> {
    if value.is_empty() {
        anyhow::bail!("allowed evaluation URI must not be empty");
    }
    Ok(value)
}

/// Requested native-evaluator mode from `AOS_NIX_NATIVE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeMode {
    /// Use the C++ Nix CLI evaluator only.
    Off,
    /// Use native evaluation as the authoritative evaluator.
    On,
    /// Run native evaluation beside C++ Nix and return the C++ Nix result.
    Shadow,
}

impl NativeMode {
    /// Parses an `AOS_NIX_NATIVE` value.
    pub fn parse(value: Option<&str>) -> Self {
        parse_native_mode(value).0
    }
}

fn parse_native_mode(value: Option<&str>) -> (NativeMode, Option<String>) {
    let Some(raw) = value else {
        return (NativeMode::Off, None);
    };
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" | "0" | "false" | "no" | "off" => (NativeMode::Off, None),
        "1" | "true" | "yes" | "on" => (NativeMode::On, None),
        "shadow" => (NativeMode::Shadow, None),
        _ => (NativeMode::Off, Some(raw.to_string())),
    }
}

/// Returns the native-evaluator mode requested by `AOS_NIX_NATIVE`.
pub fn native_mode_from_env() -> NativeMode {
    *NATIVE_MODE.get_or_init(|| {
        let value = std::env::var("AOS_NIX_NATIVE").ok();
        let (mode, unknown) = parse_native_mode(value.as_deref());
        if let Some(raw) = unknown {
            tracing::warn!(
                value = raw,
                "unknown AOS_NIX_NATIVE value; using nix-cli fallback"
            );
        }
        mode
    })
}

#[cfg(feature = "native-eval")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeVerifyMode {
    Off,
    Always,
}

#[cfg(feature = "native-eval")]
impl NativeVerifyMode {
    const fn enabled(self) -> bool {
        matches!(self, Self::Always)
    }
}

#[cfg(feature = "native-eval")]
fn parse_native_verify_mode(value: Option<&str>) -> (NativeVerifyMode, Option<String>) {
    let Some(raw) = value else {
        return (NativeVerifyMode::Off, None);
    };
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" | "0" | "false" | "no" | "off" => (NativeVerifyMode::Off, None),
        "1" | "true" | "yes" | "on" | "always" => (NativeVerifyMode::Always, None),
        _ => (NativeVerifyMode::Off, Some(raw.to_string())),
    }
}

#[cfg(feature = "native-eval")]
fn native_verify_mode_from_env() -> NativeVerifyMode {
    *NATIVE_VERIFY_MODE.get_or_init(|| {
        let value = std::env::var("AOS_NIX_NATIVE_VERIFY").ok();
        let (mode, unknown) = parse_native_verify_mode(value.as_deref());
        if let Some(raw) = unknown {
            tracing::warn!(
                value = raw,
                "unknown AOS_NIX_NATIVE_VERIFY value; disabling native verification"
            );
        }
        mode
    })
}

/// Selects the active evaluator using `AOS_NIX_NATIVE`.
///
/// The native crate is not linked into `aos-core`; when native or shadow mode is
/// requested without an integration layer, this factory warns and returns the
/// permanent C++ Nix fallback.
///
/// # Errors
///
/// This function currently has no fallible initialization path. It returns
/// `Result` so callers can keep the same shape when a native provider is wired
/// above `aos-core`.
pub fn select_evaluator(verbose: u8) -> Result<Box<dyn NixEval>> {
    select_evaluator_with_config(verbose, NixEvalConfig::default())
}

/// Selects the active evaluator using `AOS_NIX_NATIVE` and explicit settings.
///
/// # Errors
///
/// Returns an error if the selected native evaluator cannot be initialized with
/// the supplied settings.
pub fn select_evaluator_with_config(
    verbose: u8,
    config: NixEvalConfig,
) -> Result<Box<dyn NixEval>> {
    match native_mode_from_env() {
        NativeMode::Off => Ok(Box::new(NixCli::with_eval_config(verbose, config))),
        #[cfg(feature = "native-eval")]
        NativeMode::On | NativeMode::Shadow if config.eval_mode() == NixEvalMode::Ambient => {
            tracing::warn!(
                "AOS_NIX_NATIVE requested with ambient Nix eval policy; using nix-cli fallback"
            );
            Ok(Box::new(NixCli::with_eval_config(verbose, config)))
        }
        #[cfg(feature = "native-eval")]
        NativeMode::On => Ok(Box::new(NativeFallbackEval::new(verbose, config)?)),
        #[cfg(feature = "native-eval")]
        NativeMode::Shadow => Ok(Box::new(ShadowEval::new(verbose, config)?)),
        #[cfg(not(feature = "native-eval"))]
        NativeMode::On | NativeMode::Shadow => {
            tracing::warn!(
                "AOS_NIX_NATIVE requested but no native provider is linked; using nix-cli"
            );
            Ok(Box::new(NixCli::with_eval_config(verbose, config)))
        }
    }
}

/// Selects the raw native evaluator for differential `.drv` comparison.
///
/// Unlike [`select_evaluator_with_config`], this does not wrap native
/// evaluation in transparent C++ Nix fallback. Unsupported native features
/// surface as native errors so the diff harness can report them as candidate
/// divergences instead of comparing `nix-cli` to itself.
///
/// # Errors
///
/// Returns an error if the binary was built without the `native-eval` feature,
/// or if the native evaluator cannot be initialized with the supplied settings.
pub fn select_native_diff_candidate_with_config(
    verbose: u8,
    config: NixEvalConfig,
) -> Result<Box<dyn NixEval>> {
    #[cfg(feature = "native-eval")]
    {
        if config.eval_mode() == NixEvalMode::Ambient {
            anyhow::bail!(
                "native diff candidate requires an explicit evaluation mode; configure impure, pure, or restricted eval"
            );
        }
        Ok(Box::new(NativeOnlyEval::new(verbose, config)?))
    }

    #[cfg(not(feature = "native-eval"))]
    {
        let _ = (verbose, config);
        anyhow::bail!("aos nix-diff requires the native-eval feature")
    }
}

#[cfg(feature = "native-eval")]
struct NativeFallbackEval {
    native: NixNative,
    fallback: NixCli,
    config: NixEvalConfig,
}

#[cfg(feature = "native-eval")]
impl NativeFallbackEval {
    fn new(verbose: u8, config: NixEvalConfig) -> Result<Self> {
        let native_options = tree_walk_options_from_config(&config)?;
        let fallback = NixCli::with_eval_config(verbose, config.clone());
        let native = native_with_ifd_realizer(
            NixNative::with_options(verbose, native_options)?,
            verbose,
            config.clone(),
        );
        Ok(Self {
            native,
            fallback,
            config,
        })
    }
}

#[cfg(feature = "native-eval")]
impl NixEval for NativeFallbackEval {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let file = self.config.resolve_eval_file_path(file);
        match self
            .native
            .instantiate_closure(&file, attr)
            .and_then(|closure| {
                verify_native_file_drv_closure(&self.fallback, &file, attr, &closure)?;
                self.native.materialize_closure(&closure)?;
                Ok(closure.root().to_path_buf())
            }) {
            Ok(path) => {
                observe_native_eval_success(NativeSuccessOperation::FileInstantiation);
                Ok(path)
            }
            Err(error) => {
                let Some(reason) = native_cli_fallback_reason(&error) else {
                    return Err(error);
                };
                warn_native_cli_fallback(&error, reason);
                self.fallback.instantiate(&file, attr)
            }
        }
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        match self
            .native
            .instantiate_expr_closure(expr)
            .and_then(|closure| {
                verify_native_expr_drv_closure(&self.fallback, expr, &closure)?;
                self.native.materialize_closure(&closure)?;
                Ok(closure.root().to_path_buf())
            }) {
            Ok(path) => {
                observe_native_eval_success(NativeSuccessOperation::ExpressionInstantiation);
                Ok(path)
            }
            Err(error) => {
                let Some(reason) = native_cli_fallback_reason(&error) else {
                    return Err(error);
                };
                warn_native_cli_fallback(&error, reason);
                self.fallback.instantiate_expr(expr)
            }
        }
    }

    fn instantiate_expr_with_diagnostic_source(
        &self,
        expr: &str,
        diagnostic_name: &str,
        diagnostic_source: &str,
        diagnostic_range: Range<usize>,
    ) -> Result<PathBuf> {
        match self
            .native
            .instantiate_expr_closure_with_diagnostic_source(
                expr,
                diagnostic_name,
                diagnostic_source,
                diagnostic_range,
            )
            .and_then(|closure| {
                verify_native_expr_drv_closure(&self.fallback, expr, &closure)?;
                self.native.materialize_closure(&closure)?;
                Ok(closure.root().to_path_buf())
            }) {
            Ok(path) => {
                observe_native_eval_success(NativeSuccessOperation::ExpressionInstantiation);
                Ok(path)
            }
            Err(error) => {
                let Some(reason) = native_cli_fallback_reason(&error) else {
                    return Err(error);
                };
                warn_native_cli_fallback(&error, reason);
                self.fallback.instantiate_expr(expr)
            }
        }
    }

    fn eval_expr(&self, expr: &str) -> Result<String> {
        match self.native.eval_expr(expr) {
            Ok(value) => {
                verify_native_eval_expr(&self.fallback, expr, &value)?;
                observe_native_eval_success(NativeSuccessOperation::ExpressionEvaluation);
                Ok(value)
            }
            Err(error) => {
                let Some(reason) = native_cli_fallback_reason(&error) else {
                    return Err(error);
                };
                warn_native_cli_fallback(&error, reason);
                self.fallback.eval_expr(expr)
            }
        }
    }

    fn eval_expr_with_diagnostic_source(
        &self,
        expr: &str,
        diagnostic_name: &str,
        diagnostic_source: &str,
        diagnostic_range: Range<usize>,
    ) -> Result<String> {
        match self.native.eval_expr_with_diagnostic_source(
            expr,
            diagnostic_name,
            diagnostic_source,
            diagnostic_range,
        ) {
            Ok(value) => {
                verify_native_eval_expr(&self.fallback, expr, &value)?;
                observe_native_eval_success(NativeSuccessOperation::ExpressionEvaluation);
                Ok(value)
            }
            Err(error) => {
                let Some(reason) = native_cli_fallback_reason(&error) else {
                    return Err(error);
                };
                warn_native_cli_fallback(&error, reason);
                self.fallback.eval_expr(expr)
            }
        }
    }

    fn name(&self) -> &'static str {
        "aos-nix"
    }
}

#[cfg(feature = "native-eval")]
struct NativeOnlyEval {
    native: NixNative,
    config: NixEvalConfig,
}

#[cfg(feature = "native-eval")]
impl NativeOnlyEval {
    fn new(verbose: u8, config: NixEvalConfig) -> Result<Self> {
        let native_options = tree_walk_options_from_config(&config)?;
        let native = native_with_ifd_realizer(
            NixNative::with_options(verbose, native_options)?,
            verbose,
            config.clone(),
        );
        Ok(Self { native, config })
    }

    #[cfg(test)]
    fn instantiate_closure_with_stats(
        &self,
        file: &Path,
        attr: &str,
    ) -> Result<(DrvClosure, aos_nix::eval::EvalStats)> {
        let file = self.config.resolve_eval_file_path(file);
        let (closure, stats) = self.native.instantiate_closure_with_stats(&file, attr)?;
        let (root, drvs) = closure.into_parts();
        Ok((DrvClosure::new(root, drvs), stats))
    }
}

#[cfg(feature = "native-eval")]
impl NixEval for NativeOnlyEval {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let file = self.config.resolve_eval_file_path(file);
        let path = self.native.instantiate(&file, attr)?;
        observe_native_eval_success(NativeSuccessOperation::FileInstantiation);
        Ok(path)
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        let path = self.native.instantiate_expr(expr)?;
        observe_native_eval_success(NativeSuccessOperation::ExpressionInstantiation);
        Ok(path)
    }

    fn instantiate_expr_with_diagnostic_source(
        &self,
        expr: &str,
        diagnostic_name: &str,
        diagnostic_source: &str,
        diagnostic_range: Range<usize>,
    ) -> Result<PathBuf> {
        let path = self.native.instantiate_expr_with_diagnostic_source(
            expr,
            diagnostic_name,
            diagnostic_source,
            diagnostic_range,
        )?;
        observe_native_eval_success(NativeSuccessOperation::ExpressionInstantiation);
        Ok(path)
    }

    fn instantiate_closure(&self, file: &Path, attr: &str) -> Result<Option<DrvClosure>> {
        let file = self.config.resolve_eval_file_path(file);
        let closure = self.native.instantiate_closure(&file, attr)?;
        observe_native_eval_success(NativeSuccessOperation::FileInstantiation);
        let (root, drvs) = closure.into_parts();
        Ok(Some(DrvClosure::new(root, drvs)))
    }

    fn eval_expr(&self, expr: &str) -> Result<String> {
        let value = self.native.eval_expr(expr)?;
        observe_native_eval_success(NativeSuccessOperation::ExpressionEvaluation);
        Ok(value)
    }

    fn eval_expr_with_stats(&self, expr: &str) -> Result<(String, Option<NixEvalStrictJsonStats>)> {
        let (value, stats) = self.native.eval_expr_with_stats(expr)?;
        observe_native_eval_success(NativeSuccessOperation::ExpressionEvaluation);
        Ok((value, Some(NixEvalStrictJsonStats::from_native(stats))))
    }

    fn eval_expr_with_diagnostic_source(
        &self,
        expr: &str,
        diagnostic_name: &str,
        diagnostic_source: &str,
        diagnostic_range: Range<usize>,
    ) -> Result<String> {
        let value = self.native.eval_expr_with_diagnostic_source(
            expr,
            diagnostic_name,
            diagnostic_source,
            diagnostic_range,
        )?;
        observe_native_eval_success(NativeSuccessOperation::ExpressionEvaluation);
        Ok(value)
    }

    fn name(&self) -> &'static str {
        self.native.name()
    }
}

#[cfg(feature = "native-eval")]
struct ShadowEval {
    native: NixNative,
    fallback: NixCli,
    config: NixEvalConfig,
}

#[cfg(feature = "native-eval")]
impl ShadowEval {
    fn new(verbose: u8, config: NixEvalConfig) -> Result<Self> {
        let native_options = tree_walk_options_from_config(&config)?;
        let fallback = NixCli::with_eval_config(verbose, config.clone());
        let native = native_with_ifd_realizer(
            NixNative::with_options(verbose, native_options)?,
            verbose,
            config.clone(),
        );
        Ok(Self {
            native,
            fallback,
            config,
        })
    }
}

#[cfg(feature = "native-eval")]
impl NixEval for ShadowEval {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let file = self.config.resolve_eval_file_path(file);
        let fallback = self.fallback.instantiate(&file, attr)?;
        compare_shadow_file_drv_closure(&self.native, &file, attr, &fallback);
        Ok(fallback)
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        let fallback = self.fallback.instantiate_expr(expr)?;
        compare_shadow_expr_drv_closure(&self.native, expr, &fallback);
        Ok(fallback)
    }

    fn instantiate_closure(&self, file: &Path, attr: &str) -> Result<Option<DrvClosure>> {
        let file = self.config.resolve_eval_file_path(file);
        let fallback = self.fallback.instantiate_closure(&file, attr)?;
        compare_shadow_native_drv_closure(
            &fallback,
            self.native.instantiate_closure(&file, attr),
            "file instantiation",
            Some(&file),
            Some(attr),
        );
        Ok(Some(fallback))
    }

    fn eval_expr(&self, expr: &str) -> Result<String> {
        let fallback = self.fallback.eval_expr(expr)?;
        match self.native.eval_expr(expr) {
            Ok(native) if native != fallback => {
                observe_native_shadow_result(
                    NativeShadowOperation::ExpressionEvaluation,
                    NativeShadowOutcome::Divergence,
                );
                tracing::error!("shadow native eval expression result diverged from nix-cli");
            }
            Ok(_) => {
                observe_native_shadow_result(
                    NativeShadowOperation::ExpressionEvaluation,
                    NativeShadowOutcome::Match,
                );
            }
            Err(error) => {
                observe_native_shadow_result(
                    NativeShadowOperation::ExpressionEvaluation,
                    NativeShadowOutcome::Incomplete,
                );
                tracing::warn!(error = %error, "shadow native eval did not complete");
            }
        }
        Ok(fallback)
    }

    fn name(&self) -> &'static str {
        "shadow(aos-nix,nix-cli)"
    }
}

#[cfg(feature = "native-eval")]
fn compare_shadow_file_drv_closure(native: &NixNative, file: &Path, attr: &str, fallback: &Path) {
    compare_shadow_drv_closure_from_fallback_root(
        fallback,
        native.instantiate_closure(file, attr),
        "file instantiation",
        Some(file),
        Some(attr),
    );
}

#[cfg(feature = "native-eval")]
fn compare_shadow_expr_drv_closure(native: &NixNative, expr: &str, fallback: &Path) {
    compare_shadow_drv_closure_from_fallback_root(
        fallback,
        native.instantiate_expr_closure(expr),
        "expression instantiation",
        None,
        None,
    );
}

#[cfg(feature = "native-eval")]
fn compare_shadow_drv_closure_from_fallback_root(
    fallback_root: &Path,
    native: Result<NativeDrvClosure>,
    operation: &'static str,
    file: Option<&Path>,
    attr: Option<&str>,
) {
    let fallback = match read_drv_closure(fallback_root.to_path_buf()) {
        Ok(fallback) => fallback,
        Err(error) => {
            observe_native_shadow_result(
                NativeShadowOperation::DrvClosure,
                NativeShadowOutcome::Incomplete,
            );
            tracing::warn!(
                error = %error,
                fallback = %fallback_root.display(),
                operation,
                file = ?file.map(tracing_path),
                attr,
                "shadow nix-cli drv closure could not be read"
            );
            return;
        }
    };

    compare_shadow_native_drv_closure(&fallback, native, operation, file, attr);
}

#[cfg(feature = "native-eval")]
fn compare_shadow_native_drv_closure(
    fallback: &DrvClosure,
    native: Result<NativeDrvClosure>,
    operation: &'static str,
    file: Option<&Path>,
    attr: Option<&str>,
) {
    match native {
        Ok(native) => {
            let (root, drvs) = native.into_parts();
            let native = DrvClosure::new(root, drvs);
            let divergences = compare_shadow_drv_closure(fallback, &native, operation, file, attr);
            if divergences == 0 {
                observe_native_shadow_result(
                    NativeShadowOperation::DrvClosure,
                    NativeShadowOutcome::Match,
                );
                tracing::debug!(
                    operation,
                    file = ?file.map(tracing_path),
                    attr,
                    "shadow native eval drv closure matched nix-cli"
                );
            } else {
                observe_native_shadow_result(
                    NativeShadowOperation::DrvClosure,
                    NativeShadowOutcome::Divergence,
                );
            }
        }
        Err(error) => {
            observe_native_shadow_result(
                NativeShadowOperation::DrvClosure,
                NativeShadowOutcome::Incomplete,
            );
            tracing::warn!(
                error = %error,
                operation,
                file = ?file.map(tracing_path),
                attr,
                "shadow native eval drv closure did not complete"
            );
        }
    }
}

#[cfg(feature = "native-eval")]
fn compare_shadow_drv_closure(
    fallback: &DrvClosure,
    native: &DrvClosure,
    operation: &'static str,
    file: Option<&Path>,
    attr: Option<&str>,
) -> usize {
    let mut divergences = 0;
    if fallback.root() != native.root() {
        divergences += 1;
        tracing::error!(
            fallback = %fallback.root().display(),
            native = %native.root().display(),
            operation,
            file = ?file.map(tracing_path),
            attr,
            "shadow native eval drv closure root diverged from nix-cli"
        );
    }

    for (path, fallback_bytes) in fallback.drvs() {
        match native.drvs().get(path) {
            Some(native_bytes) if native_bytes == fallback_bytes => {}
            Some(_) => {
                divergences += 1;
                tracing::error!(
                    drv = %path.display(),
                    operation,
                    file = ?file.map(tracing_path),
                    attr,
                    "shadow native eval drv bytes diverged from nix-cli"
                );
            }
            None => {
                divergences += 1;
                tracing::error!(
                    drv = %path.display(),
                    operation,
                    file = ?file.map(tracing_path),
                    attr,
                    "shadow native eval omitted nix-cli drv from closure"
                );
            }
        }
    }

    for path in native.drvs().keys() {
        if !fallback.drvs().contains_key(path) {
            divergences += 1;
            tracing::error!(
                drv = %path.display(),
                operation,
                file = ?file.map(tracing_path),
                attr,
                "shadow native eval produced extra drv outside nix-cli closure"
            );
        }
    }

    divergences
}

#[cfg(feature = "native-eval")]
fn verify_native_file_drv_closure(
    fallback: &NixCli,
    file: &Path,
    attr: &str,
    native: &NativeDrvClosure,
) -> Result<()> {
    if !native_verify_mode_from_env().enabled() {
        return Ok(());
    }

    let fallback_root = match fallback.instantiate(file, attr) {
        Ok(path) => path,
        Err(error) => {
            observe_native_verify_result(
                NativeVerifyOperation::DrvClosure,
                NativeVerifyOutcome::Incomplete,
            );
            tracing::error!(
                error = %error,
                file = %file.display(),
                attr,
                "native verify oracle file instantiation failed"
            );
            return Err(anyhow::anyhow!(
                "native verify oracle file instantiation failed for {} -A {attr}: {error}",
                file.display()
            ));
        }
    };

    verify_native_drv_closure_from_fallback_root(
        &fallback_root,
        native,
        "file instantiation",
        Some(file),
        Some(attr),
    )
}

#[cfg(feature = "native-eval")]
fn verify_native_expr_drv_closure(
    fallback: &NixCli,
    expr: &str,
    native: &NativeDrvClosure,
) -> Result<()> {
    if !native_verify_mode_from_env().enabled() {
        return Ok(());
    }

    let fallback_root = match fallback.instantiate_expr(expr) {
        Ok(path) => path,
        Err(error) => {
            observe_native_verify_result(
                NativeVerifyOperation::DrvClosure,
                NativeVerifyOutcome::Incomplete,
            );
            tracing::error!(
                error = %error,
                "native verify oracle expression instantiation failed"
            );
            return Err(anyhow::anyhow!(
                "native verify oracle expression instantiation failed: {error}"
            ));
        }
    };

    verify_native_drv_closure_from_fallback_root(
        &fallback_root,
        native,
        "expression instantiation",
        None,
        None,
    )
}

#[cfg(feature = "native-eval")]
fn verify_native_drv_closure_from_fallback_root(
    fallback_root: &Path,
    native: &NativeDrvClosure,
    operation: &'static str,
    file: Option<&Path>,
    attr: Option<&str>,
) -> Result<()> {
    let fallback = match read_drv_closure(fallback_root.to_path_buf()) {
        Ok(closure) => closure,
        Err(error) => {
            observe_native_verify_result(
                NativeVerifyOperation::DrvClosure,
                NativeVerifyOutcome::Incomplete,
            );
            tracing::error!(
                error = %error,
                fallback = %fallback_root.display(),
                native = %native.root().display(),
                operation,
                "native verify could not read nix-cli drv closure"
            );
            return Err(anyhow::anyhow!(
                "native verify could not read nix-cli drv closure {}: {error}",
                fallback_root.display()
            ));
        }
    };

    let divergences = compare_verify_drv_closure(&fallback, &native, operation, file, attr);
    if divergences == 0 {
        observe_native_verify_result(
            NativeVerifyOperation::DrvClosure,
            NativeVerifyOutcome::Match,
        );
        tracing::debug!(operation, "native verify drv closure matched nix-cli");
        Ok(())
    } else {
        observe_native_verify_result(
            NativeVerifyOperation::DrvClosure,
            NativeVerifyOutcome::Divergence,
        );
        Err(anyhow::anyhow!(
            "native verify found {divergences} drv closure divergence(s) for {operation}"
        ))
    }
}

#[cfg(feature = "native-eval")]
fn compare_verify_drv_closure(
    fallback: &DrvClosure,
    native: &NativeDrvClosure,
    operation: &'static str,
    file: Option<&Path>,
    attr: Option<&str>,
) -> usize {
    let mut divergences = 0;
    if fallback.root() != native.root() {
        divergences += 1;
        tracing::error!(
            fallback = %fallback.root().display(),
            native = %native.root().display(),
            operation,
            file = ?file.map(tracing_path),
            attr,
            "native verify drv closure root diverged from nix-cli"
        );
    }

    for (path, fallback_bytes) in fallback.drvs() {
        match native.drvs().get(path) {
            Some(native_bytes) if native_bytes == fallback_bytes => {}
            Some(_) => {
                divergences += 1;
                tracing::error!(
                    drv = %path.display(),
                    operation,
                    file = ?file.map(tracing_path),
                    attr,
                    "native verify drv bytes diverged from nix-cli"
                );
            }
            None => {
                divergences += 1;
                tracing::error!(
                    drv = %path.display(),
                    operation,
                    file = ?file.map(tracing_path),
                    attr,
                    "native verify omitted nix-cli drv from closure"
                );
            }
        }
    }

    for path in native.drvs().keys() {
        if !fallback.drvs().contains_key(path) {
            divergences += 1;
            tracing::error!(
                drv = %path.display(),
                operation,
                file = ?file.map(tracing_path),
                attr,
                "native verify produced extra drv outside nix-cli closure"
            );
        }
    }

    divergences
}

#[cfg(feature = "native-eval")]
fn verify_native_eval_expr(fallback: &NixCli, expr: &str, native: &str) -> Result<()> {
    if !native_verify_mode_from_env().enabled() {
        return Ok(());
    }

    let fallback = match fallback.eval_expr(expr) {
        Ok(value) => value,
        Err(error) => {
            observe_native_verify_result(
                NativeVerifyOperation::ExpressionEvaluation,
                NativeVerifyOutcome::Incomplete,
            );
            tracing::error!(
                error = %error,
                "native verify oracle expression evaluation failed"
            );
            return Err(anyhow::anyhow!(
                "native verify oracle expression evaluation failed: {error}"
            ));
        }
    };
    if fallback == native {
        observe_native_verify_result(
            NativeVerifyOperation::ExpressionEvaluation,
            NativeVerifyOutcome::Match,
        );
        tracing::debug!("native verify expression evaluation matched nix-cli");
        Ok(())
    } else {
        observe_native_verify_result(
            NativeVerifyOperation::ExpressionEvaluation,
            NativeVerifyOutcome::Divergence,
        );
        tracing::error!("native verify expression evaluation diverged from nix-cli");
        Err(anyhow::anyhow!(
            "native verify expression evaluation diverged from nix-cli"
        ))
    }
}

#[cfg(feature = "native-eval")]
fn tracing_path(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(feature = "native-eval")]
#[derive(Debug, Clone, Copy)]
enum NativeSuccessOperation {
    FileInstantiation,
    ExpressionInstantiation,
    ExpressionEvaluation,
}

#[cfg(feature = "native-eval")]
impl NativeSuccessOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::FileInstantiation => "file instantiation",
            Self::ExpressionInstantiation => "expression instantiation",
            Self::ExpressionEvaluation => "expression evaluation",
        }
    }
}

#[cfg(feature = "native-eval")]
#[derive(Debug, Clone, Copy)]
enum NativeShadowOperation {
    DrvClosure,
    ExpressionEvaluation,
}

#[cfg(feature = "native-eval")]
impl NativeShadowOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::DrvClosure => "drv closure",
            Self::ExpressionEvaluation => "expression evaluation",
        }
    }
}

#[cfg(feature = "native-eval")]
#[derive(Debug, Clone, Copy)]
enum NativeShadowOutcome {
    Match,
    Divergence,
    Incomplete,
}

#[cfg(feature = "native-eval")]
impl NativeShadowOutcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Divergence => "divergence",
            Self::Incomplete => "incomplete",
        }
    }
}

#[cfg(feature = "native-eval")]
#[derive(Debug, Clone, Copy)]
enum NativeVerifyOperation {
    DrvClosure,
    ExpressionEvaluation,
}

#[cfg(feature = "native-eval")]
impl NativeVerifyOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::DrvClosure => "drv closure",
            Self::ExpressionEvaluation => "expression evaluation",
        }
    }
}

#[cfg(feature = "native-eval")]
#[derive(Debug, Clone, Copy)]
enum NativeVerifyOutcome {
    Match,
    Divergence,
    Incomplete,
}

#[cfg(feature = "native-eval")]
impl NativeVerifyOutcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Divergence => "divergence",
            Self::Incomplete => "incomplete",
        }
    }
}

#[cfg(feature = "native-eval")]
fn native_cli_fallback_reason(error: &anyhow::Error) -> Option<NativeCliFallbackReason> {
    error
        .downcast_ref::<NativeEvalError>()
        .and_then(NativeEvalError::cli_fallback_reason)
}

#[cfg(feature = "native-eval")]
fn native_with_ifd_realizer(native: NixNative, verbose: u8, config: NixEvalConfig) -> NixNative {
    let realizer = NixCli::with_eval_config(verbose, config);
    native.with_ifd_realizer(IfdRealizer::new(move |request| {
        let drv = std::str::from_utf8(request.drv_path()).map_err(|source| {
            IfdRealizationError::new(format!("IFD derivation path is not UTF-8: {source}"))
        })?;
        realizer
            .realise(drv)
            .map(|_| ())
            .map_err(|source| IfdRealizationError::new(source.to_string()))
    }))
}

#[cfg(feature = "native-eval")]
fn warn_native_cli_fallback(error: &anyhow::Error, reason: NativeCliFallbackReason) {
    let count = record_native_cli_fallback(reason);
    tracing::warn!(
        evaluator = "aos-nix",
        fallback_evaluator = "nix-cli",
        error = %error,
        fallback_reason = ?reason,
        fallback_count = count,
        "native eval fell back to nix-cli"
    );
}

#[cfg(feature = "native-eval")]
fn observe_native_eval_success(operation: NativeSuccessOperation) {
    let count = record_native_eval_success(operation);
    tracing::debug!(
        operation = operation.label(),
        native_success_count = count,
        "native eval completed without nix-cli fallback"
    );
}

#[cfg(feature = "native-eval")]
fn observe_native_shadow_result(operation: NativeShadowOperation, outcome: NativeShadowOutcome) {
    let count = record_native_shadow_result(operation, outcome);
    tracing::debug!(
        operation = operation.label(),
        shadow_outcome = outcome.label(),
        shadow_count = count,
        "shadow native eval comparison recorded"
    );
}

#[cfg(feature = "native-eval")]
fn observe_native_verify_result(operation: NativeVerifyOperation, outcome: NativeVerifyOutcome) {
    let count = record_native_verify_result(operation, outcome);
    tracing::debug!(
        operation = operation.label(),
        verify_outcome = outcome.label(),
        verify_count = count,
        "native verify comparison recorded"
    );
}

#[cfg(feature = "native-eval")]
fn record_native_shadow_result(
    operation: NativeShadowOperation,
    outcome: NativeShadowOutcome,
) -> u64 {
    let counter = match (operation, outcome) {
        (NativeShadowOperation::DrvClosure, NativeShadowOutcome::Match) => &NATIVE_SHADOW_DRV_MATCH,
        (NativeShadowOperation::DrvClosure, NativeShadowOutcome::Divergence) => {
            &NATIVE_SHADOW_DRV_DIVERGENCE
        }
        (NativeShadowOperation::DrvClosure, NativeShadowOutcome::Incomplete) => {
            &NATIVE_SHADOW_DRV_INCOMPLETE
        }
        (NativeShadowOperation::ExpressionEvaluation, NativeShadowOutcome::Match) => {
            &NATIVE_SHADOW_EXPRESSION_MATCH
        }
        (NativeShadowOperation::ExpressionEvaluation, NativeShadowOutcome::Divergence) => {
            &NATIVE_SHADOW_EXPRESSION_DIVERGENCE
        }
        (NativeShadowOperation::ExpressionEvaluation, NativeShadowOutcome::Incomplete) => {
            &NATIVE_SHADOW_EXPRESSION_INCOMPLETE
        }
    };
    counter.fetch_add(1, Ordering::Relaxed) + 1
}

#[cfg(feature = "native-eval")]
fn record_native_verify_result(
    operation: NativeVerifyOperation,
    outcome: NativeVerifyOutcome,
) -> u64 {
    let counter = match (operation, outcome) {
        (NativeVerifyOperation::DrvClosure, NativeVerifyOutcome::Match) => &NATIVE_VERIFY_DRV_MATCH,
        (NativeVerifyOperation::DrvClosure, NativeVerifyOutcome::Divergence) => {
            &NATIVE_VERIFY_DRV_DIVERGENCE
        }
        (NativeVerifyOperation::DrvClosure, NativeVerifyOutcome::Incomplete) => {
            &NATIVE_VERIFY_DRV_INCOMPLETE
        }
        (NativeVerifyOperation::ExpressionEvaluation, NativeVerifyOutcome::Match) => {
            &NATIVE_VERIFY_EXPRESSION_MATCH
        }
        (NativeVerifyOperation::ExpressionEvaluation, NativeVerifyOutcome::Divergence) => {
            &NATIVE_VERIFY_EXPRESSION_DIVERGENCE
        }
        (NativeVerifyOperation::ExpressionEvaluation, NativeVerifyOutcome::Incomplete) => {
            &NATIVE_VERIFY_EXPRESSION_INCOMPLETE
        }
    };
    counter.fetch_add(1, Ordering::Relaxed) + 1
}

#[cfg(feature = "native-eval")]
fn record_native_eval_success(operation: NativeSuccessOperation) -> u64 {
    let counter = match operation {
        NativeSuccessOperation::FileInstantiation => &NATIVE_SUCCESS_FILE_INSTANTIATION,
        NativeSuccessOperation::ExpressionInstantiation => &NATIVE_SUCCESS_EXPRESSION_INSTANTIATION,
        NativeSuccessOperation::ExpressionEvaluation => &NATIVE_SUCCESS_EXPRESSION_EVALUATION,
    };
    counter.fetch_add(1, Ordering::Relaxed) + 1
}

#[cfg(feature = "native-eval")]
fn record_native_cli_fallback(reason: NativeCliFallbackReason) -> u64 {
    let counter = match reason {
        NativeCliFallbackReason::Unsupported => &NATIVE_FALLBACK_UNSUPPORTED,
        NativeCliFallbackReason::Internal => &NATIVE_FALLBACK_INTERNAL,
    };
    counter.fetch_add(1, Ordering::Relaxed) + 1
}

/// One snapshot of the raw `AOS_NIX_MEMO*` environment values.
#[derive(Clone, Debug, Default)]
struct EnvMemoKnobs {
    master: Option<String>,
    l0: Option<String>,
    l1: Option<String>,
    l2: Option<String>,
    min_cost: Option<String>,
    l0_entries: Option<String>,
    l1_bytes: Option<String>,
    promote_hits: Option<String>,
    check: Option<String>,
    disk: Option<String>,
    net: Option<String>,
    net_mode: Option<String>,
    net_timeout_ms: Option<String>,
}

impl EnvMemoKnobs {
    /// Captures the process environment's memo knobs.
    fn from_process() -> Self {
        Self {
            master: std::env::var("AOS_NIX_MEMO").ok(),
            l0: std::env::var("AOS_NIX_MEMO_L0").ok(),
            l1: std::env::var("AOS_NIX_MEMO_L1").ok(),
            l2: std::env::var("AOS_NIX_MEMO_L2").ok(),
            min_cost: std::env::var("AOS_NIX_MEMO_MIN_COST").ok(),
            l0_entries: std::env::var("AOS_NIX_MEMO_L0_ENTRIES").ok(),
            l1_bytes: std::env::var("AOS_NIX_MEMO_L1_BYTES").ok(),
            promote_hits: std::env::var("AOS_NIX_MEMO_PROMOTE_HITS").ok(),
            check: std::env::var("AOS_NIX_MEMO_CHECK").ok(),
            disk: std::env::var("AOS_NIX_MEMO_DISK").ok(),
            net: std::env::var("AOS_NIX_MEMO_NET").ok(),
            net_mode: std::env::var("AOS_NIX_MEMO_NET_MODE").ok(),
            net_timeout_ms: std::env::var("AOS_NIX_MEMO_NET_TIMEOUT_MS").ok(),
        }
    }
}

/// True for the truthy switch spellings accepted by the memo knobs.
fn env_flag_is_truthy(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "on" | "yes")
}

/// True for the falsy switch spellings shared by the existing kill switches.
fn env_flag_is_falsy(value: &str) -> bool {
    matches!(value.trim(), "0" | "false" | "off" | "no")
}

#[cfg(feature = "native-eval")]
fn tree_walk_options_from_config(config: &NixEvalConfig) -> Result<TreeWalkOptions> {
    let mut options = TreeWalkOptions::new();
    options.set_eval_mode(match config.eval_mode() {
        NixEvalMode::Ambient => {
            anyhow::bail!("native evaluator requires an explicit evaluation mode")
        }
        NixEvalMode::Impure => EvalMode::Impure,
        NixEvalMode::Restricted => EvalMode::Restricted,
        NixEvalMode::Pure => EvalMode::Pure,
    });
    if config.eval_mode() == NixEvalMode::Restricted {
        for path in config.allowed_paths() {
            options.add_allowed_path(path.as_bytes().to_vec())?;
        }
        for uri in config.allowed_uris() {
            options.add_allowed_uri(uri.as_bytes().to_vec())?;
        }
    }
    for (name, value) in &config.eval_env_vars {
        options.set_env_var(name.clone(), value.clone());
    }
    if let Some(working_dir) = config.working_dir() {
        let working_dir = path_bytes(working_dir);
        options.set_search_path_base(working_dir.clone())?;
        options.set_path_literal_base(working_dir)?;
    }
    if let Some(home_dir) = config.home_dir() {
        options.set_home_dir(path_bytes(home_dir))?;
    }
    if let Some(nix_path) = config.nix_path_env() {
        if let Some(entries) = native_nix_path_entries_from_env_value(nix_path) {
            let entries = entries
                .into_iter()
                .map(|entry| {
                    NixSearchPathEntry::new(entry.prefix.into_bytes(), entry.path.into_bytes())
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            options.set_nix_path(entries);
        } else {
            options.set_reject_ambient_search_path(true);
        }
    } else {
        options.set_reject_ambient_search_path(true);
    }
    if let Some(store_dir) = config.store_dir() {
        options.set_store_dir(store_dir.as_bytes().to_vec())?;
    }
    if let Some(current_system) = config.current_system() {
        options.set_current_system(current_system.as_bytes().to_vec())?;
    }
    if let Some(cache_root) = config.native_cache_root() {
        options.set_parse_cache_root(cache_root.join("parse"));
        options.set_persist_cache_root(cache_root.join("persist"));
        options.set_eval_cache_enabled(true);
        options.set_persist_cache_verify(config.native_cache_verify());
        options.set_root_cutoff_enabled(config.native_root_cutoff());
        options.set_root_cutoff_check(config.native_root_cutoff_check());
        // Secondary L2 disk locations and the L3 network tier are additive to
        // the primary cache root, so both are configured only alongside it.
        // Each configured secondary spec names a cache-root directory whose
        // `persist/` child mirrors the primary's layout.
        if let Some(spec) = config.native_memo_disk_spec() {
            match aos_nix::cache::PersistDiskLocation::parse_list(spec) {
                Ok(locations) => {
                    let locations = locations
                        .into_iter()
                        .map(|location| {
                            aos_nix::cache::PersistDiskLocation::new(
                                location.class(),
                                location.root().join("persist"),
                            )
                        })
                        .collect();
                    options.set_memo_disk_locations(locations);
                }
                Err(error) => tracing::warn!(
                    error = %error,
                    spec,
                    "invalid AOS_NIX_MEMO_DISK value; disabling secondary cache locations"
                ),
            }
        }
        if let Some(net) = config.native_memo_net() {
            options.set_memo_net(Some(MemoNetOptions {
                endpoint: net.endpoint.clone(),
                mode: if net.writable {
                    MemoNetMode::ReadWrite
                } else {
                    MemoNetMode::ReadOnly
                },
                timeout_ms: net.timeout_ms,
            }));
        }
    }
    if let Some(max_resident_bytes) = config.heap_memory_budget_bytes() {
        options.set_heap_memory_budget(HeapMemoryBudget::new(max_resident_bytes)?);
        options.set_heap_tier_b_transition_admission_enabled(true);
    }
    options.set_trace_verbose(config.trace_verbose());
    options.set_eval_stats_dump(config.native_eval_stats());
    let memo = config.native_memo();
    options.set_memo_options(MemoOptions {
        enabled: memo.enabled,
        l0_enabled: memo.l0_enabled,
        l1_enabled: memo.l1_enabled,
        min_cost: memo.min_cost,
        l0_entries: memo.l0_entries,
        l1_bytes: memo.l1_bytes,
        promote_hits: memo.promote_hits,
        check_l0: memo.check_l0,
        check_l1: memo.check_l1,
        l2_enabled: memo.l2_enabled,
        check_l2: memo.check_l2,
        check_l3: memo.check_l3,
    });
    options.set_jit_tier1_publish_enabled(config.native_jit());
    // Parallel mode overrides the JIT flag: the tier-1 engine is worker-affine
    // and is never installed when parallel workers are configured.
    options.set_parallel_workers(config.native_parallel_workers());
    if config.native_parallel_workers().is_some() {
        options.set_jit_tier1_publish_enabled(false);
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "native-eval")]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(all(feature = "native-eval", unix))]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(feature = "native-eval")]
    use std::sync::{Arc, Mutex};
    #[cfg(feature = "native-eval")]
    use tracing::field::{Field, Visit};
    #[cfg(feature = "native-eval")]
    use tracing::{Event, Level, Metadata, Subscriber, span};

    #[cfg(unix)]
    fn command_env_bytes(command: &Command, name: &[u8]) -> Option<Vec<u8>> {
        command.get_envs().find_map(|(key, value)| {
            (key.as_bytes() == name).then(|| value.map(|value| value.as_bytes().to_vec()))?
        })
    }

    #[cfg(not(unix))]
    fn command_env_bytes(command: &Command, name: &[u8]) -> Option<Vec<u8>> {
        let name = String::from_utf8_lossy(name);
        command.get_envs().find_map(|(key, value)| {
            (key.to_string_lossy() == name)
                .then(|| value.map(|value| value.to_string_lossy().into_owned().into_bytes()))?
        })
    }

    #[cfg(all(feature = "native-eval", unix))]
    struct PermissionRestoreGuard {
        path: PathBuf,
        permissions: Option<fs::Permissions>,
    }

    #[cfg(all(feature = "native-eval", unix))]
    impl PermissionRestoreGuard {
        fn new(path: &Path) -> Result<Self> {
            Ok(Self {
                path: path.to_path_buf(),
                permissions: Some(fs::metadata(path)?.permissions()),
            })
        }

        fn restore(mut self) -> Result<()> {
            if let Some(permissions) = self.permissions.take() {
                fs::set_permissions(&self.path, permissions)?;
            }
            Ok(())
        }
    }

    #[cfg(all(feature = "native-eval", unix))]
    impl Drop for PermissionRestoreGuard {
        fn drop(&mut self) {
            if let Some(permissions) = self.permissions.take() {
                let _ = fs::set_permissions(&self.path, permissions);
            }
        }
    }

    #[cfg(feature = "native-eval")]
    fn assert_persistent_force_cache_payload_entries(persist_root: &Path) -> Result<()> {
        let persist = aos_nix::cache::PersistCache::open(persist_root)?;
        let has_materialized_payload = persist
            .node_metadata_index()
            .latest_entries()?
            .into_iter()
            .any(|entry| {
                entry.value().materialized_value_hash().is_some()
                    && matches!(
                        persist.load_cached_expression_node_value_indexed(entry.key()),
                        Ok(Some(_))
                    )
            });
        assert!(
            has_materialized_payload,
            "native force-cache run should write a loadable persistent forced-expression payload"
        );
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    fn assert_no_incremental_cache_stats(stats: &aos_nix::eval::EvalStats, label: &str) {
        assert_eq!(
            stats.force_cache_hits(),
            0,
            "{label} reported force-cache hits"
        );
        assert_eq!(
            stats.force_cache_misses(),
            0,
            "{label} reported force-cache misses"
        );
        assert_eq!(
            stats.cache_hits(),
            0,
            "{label} reported aggregate evaluator cache hits"
        );
        assert_eq!(
            stats.cache_misses(),
            0,
            "{label} reported aggregate evaluator cache misses"
        );
        assert_eq!(
            stats.force_cache_memoization_admits(),
            0,
            "{label} reported force-cache memoization admit decisions"
        );
        assert_eq!(
            stats.force_cache_memoization_bypasses(),
            0,
            "{label} reported force-cache memoization bypass decisions"
        );
        assert_eq!(
            stats.force_cache_memoization_demands(),
            0,
            "{label} reported force-cache memoization demand decisions"
        );
        assert_eq!(
            stats.force_cache_materialization_materializes(),
            0,
            "{label} reported durable force-cache materialization decisions"
        );
        assert_eq!(
            stats.force_cache_materialization_keeps_in_memory(),
            0,
            "{label} reported in-memory force-cache materialization decisions"
        );
        assert_eq!(
            stats.force_cache_materialization_decisions(),
            0,
            "{label} reported force-cache materialization decisions"
        );
        assert_eq!(
            stats.early_cutoffs(),
            0,
            "{label} reported incremental-cache early cutoffs"
        );
        assert_eq!(
            stats.derivation_aterm_path_reuses(),
            0,
            "{label} reported derivation ATerm path reuse"
        );
        assert_eq!(
            stats.static_derivation_output_path_reuses(),
            0,
            "{label} reported static derivation output path reuse"
        );
    }

    #[cfg(feature = "native-eval")]
    fn snapshot_regular_file_tree(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
        let mut snapshot = BTreeMap::new();
        if root.exists() {
            snapshot_regular_file_tree_at(root, root, &mut snapshot)?;
        }
        Ok(snapshot)
    }

    #[cfg(feature = "native-eval")]
    fn snapshot_regular_file_tree_at(
        root: &Path,
        current: &Path,
        snapshot: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<()> {
        let mut entries = fs::read_dir(current)?.collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                snapshot_regular_file_tree_at(root, &path, snapshot)?;
            } else if file_type.is_file() {
                let relative = path.strip_prefix(root)?.to_path_buf();
                assert!(
                    snapshot.insert(relative, fs::read(path)?).is_none(),
                    "persistent cache snapshot should not see duplicate paths"
                );
            }
        }
        Ok(())
    }

    #[cfg(all(feature = "native-eval", unix))]
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum CacheRootSnapshotEntry {
        Directory,
        File(Vec<u8>),
        Symlink(PathBuf),
    }

    #[cfg(all(feature = "native-eval", unix))]
    fn snapshot_cache_root_tree(root: &Path) -> Result<BTreeMap<PathBuf, CacheRootSnapshotEntry>> {
        let mut snapshot = BTreeMap::new();
        if fs::symlink_metadata(root).is_ok() {
            snapshot_cache_root_tree_at(root, root, &mut snapshot)?;
        }
        Ok(snapshot)
    }

    #[cfg(all(feature = "native-eval", unix))]
    fn snapshot_cache_root_tree_at(
        root: &Path,
        current: &Path,
        snapshot: &mut BTreeMap<PathBuf, CacheRootSnapshotEntry>,
    ) -> Result<()> {
        let metadata = fs::symlink_metadata(current)?;
        let relative = current.strip_prefix(root).unwrap_or(Path::new("."));
        let relative = if relative.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            relative.to_path_buf()
        };
        let file_type = metadata.file_type();
        let entry = if file_type.is_dir() {
            CacheRootSnapshotEntry::Directory
        } else if file_type.is_symlink() {
            CacheRootSnapshotEntry::Symlink(fs::read_link(current)?)
        } else if file_type.is_file() {
            CacheRootSnapshotEntry::File(fs::read(current)?)
        } else {
            return Ok(());
        };
        assert!(
            snapshot.insert(relative, entry).is_none(),
            "cache-root snapshot should not see duplicate paths"
        );
        if file_type.is_dir() {
            let mut entries = fs::read_dir(current)?.collect::<std::result::Result<Vec<_>, _>>()?;
            entries.sort_by_key(|entry| entry.path());
            for entry in entries {
                snapshot_cache_root_tree_at(root, &entry.path(), snapshot)?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[derive(Clone)]
    struct FallbackWarningSubscriber {
        events: Arc<Mutex<Vec<(Level, String)>>>,
    }

    #[cfg(feature = "native-eval")]
    impl Subscriber for FallbackWarningSubscriber {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            *metadata.level() <= Level::WARN
        }

        fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}
        fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}
        fn enter(&self, _span: &span::Id) {}
        fn exit(&self, _span: &span::Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut visitor = FallbackWarningFields::default();
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("recorded fallback events lock")
                .push((*event.metadata().level(), visitor.render()));
        }
    }

    #[cfg(feature = "native-eval")]
    #[derive(Default)]
    struct FallbackWarningFields {
        message: String,
        fields: Vec<String>,
    }

    #[cfg(feature = "native-eval")]
    impl FallbackWarningFields {
        fn render(self) -> String {
            let mut output = self.message;
            for field in self.fields {
                if !output.is_empty() {
                    output.push(' ');
                }
                output.push_str(&field);
            }
            output
        }
    }

    #[cfg(feature = "native-eval")]
    impl Visit for FallbackWarningFields {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = format!("{value:?}");
            } else {
                self.fields.push(format!("{}={value:?}", field.name()));
            }
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.fields.push(format!("{}={value}", field.name()));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "message" {
                self.message = value.to_string();
            } else {
                self.fields.push(format!("{}={value}", field.name()));
            }
        }
    }

    #[test]
    fn eval_config_rejects_empty_current_system() {
        let error = NixEvalConfig::with_current_system("")
            .expect_err("empty currentSystem should be invalid");

        assert!(error.to_string().contains("currentSystem"));
    }

    #[test]
    fn eval_config_rejects_relative_store_dirs() {
        let error = NixEvalConfig::with_store_dirs("relative/store", "/aos/var/nix", "/aos/log")
            .expect_err("relative store dir should be invalid");

        assert!(error.to_string().contains("NIX_STORE_DIR"));
    }

    #[test]
    fn eval_config_rejects_relative_native_cache_root() {
        let mut config = NixEvalConfig::new();
        let error = config
            .set_native_cache_root("relative/cache")
            .expect_err("relative native cache root should be invalid");

        assert!(error.to_string().contains("AOS_NIX_CACHE"));
    }

    #[test]
    fn eval_config_parses_memo_env_knobs() {
        let mut config = NixEvalConfig::new();
        config.set_aos_nix_memo_env_vars(EnvMemoKnobs {
            master: Some("1".to_owned()),
            l0: Some("off".to_owned()),
            l1: Some("true".to_owned()),
            min_cost: Some("128".to_owned()),
            l0_entries: Some("1024".to_owned()),
            l1_bytes: Some("4096".to_owned()),
            promote_hits: Some("3".to_owned()),
            check: Some("l0,l1".to_owned()),
            l2: Some("off".to_owned()),
            disk: Some("hdd:/bulk/cache".to_owned()),
            net: Some("http://memo.example/base/".to_owned()),
            net_mode: Some("rw".to_owned()),
            net_timeout_ms: Some("750".to_owned()),
        });
        let memo = config.native_memo();
        assert!(memo.enabled);
        assert!(!memo.l0_enabled);
        assert_eq!(memo.l1_enabled, Some(true));
        assert_eq!(memo.min_cost, 128);
        assert_eq!(memo.l0_entries, 1024);
        assert_eq!(memo.l1_bytes, 4096);
        assert_eq!(memo.promote_hits, 3);
        assert!(memo.check_l0);
        assert!(memo.check_l1);
        assert!(!memo.l2_enabled);
        assert!(!memo.check_l2);
        assert!(!memo.check_l3);
        assert_eq!(config.native_memo_disk_spec(), Some("hdd:/bulk/cache"));
        let net = config.native_memo_net().expect("net settings parse");
        assert_eq!(net.endpoint, "http://memo.example/base");
        assert!(net.writable);
        assert_eq!(net.timeout_ms, 750);

        // Invalid numeric values keep the previous settings; `all` selects
        // both CHECK tiers; falsy master disables.
        config.set_aos_nix_memo_env_vars(EnvMemoKnobs {
            master: Some("off".to_owned()),
            min_cost: Some("not-a-number".to_owned()),
            check: Some("all".to_owned()),
            ..EnvMemoKnobs::default()
        });
        let memo = config.native_memo();
        assert!(!memo.enabled);
        assert_eq!(memo.min_cost, 128);
        assert!(memo.check_l0);
        assert!(memo.check_l1);
        assert!(memo.check_l2);
        assert!(memo.check_l3);
    }

    #[test]
    fn eval_config_rejects_relative_home_dir() {
        let mut config = NixEvalConfig::new();
        let error = config
            .set_home_dir("relative/home")
            .expect_err("relative home dir should be invalid");

        assert!(error.to_string().contains("HOME"));
    }

    #[test]
    fn eval_config_rejects_missing_working_dir() {
        let parent = tempfile::tempdir().expect("tempdir creates");
        let mut config = NixEvalConfig::new();
        let error = config
            .set_working_dir(parent.path().join("does-not-exist"))
            .expect_err("missing working dir should be invalid");

        assert!(error.to_string().contains("existing directory"));
    }

    #[test]
    fn eval_config_resolves_relative_eval_file_paths_against_working_dir() -> Result<()> {
        let working_dir = tempfile::tempdir()?;
        let mut config = NixEvalConfig::new();
        config.set_working_dir(working_dir.path())?;

        assert_eq!(
            config.resolve_eval_file_path(Path::new("default.nix")),
            working_dir.path().join("default.nix")
        );
        assert_eq!(
            config.resolve_eval_file_path(Path::new("/already/absolute.nix")),
            PathBuf::from("/already/absolute.nix")
        );
        Ok(())
    }

    #[test]
    fn eval_config_rejects_relative_allowed_paths() {
        let mut config = NixEvalConfig::new();
        let error = config
            .add_allowed_path("relative/path")
            .expect_err("relative allowed path should be invalid");

        assert!(error.to_string().contains("allowed evaluation path"));
    }

    #[test]
    fn eval_config_rejects_whitespace_allowed_paths() {
        let mut config = NixEvalConfig::new();
        let error = config
            .add_allowed_path("/aos/source tree")
            .expect_err("whitespace allowed path should be invalid");

        assert!(error.to_string().contains("whitespace"));
    }

    #[test]
    fn eval_config_rejects_empty_allowed_uris() {
        let mut config = NixEvalConfig::new();
        let error = config
            .add_allowed_uri("")
            .expect_err("empty allowed URI should be invalid");

        assert!(error.to_string().contains("allowed evaluation URI"));
    }

    #[test]
    fn eval_config_parses_aos_nix_cache_env_values() {
        assert_eq!(native_cache_root_from_env_value("0"), None);
        assert_eq!(native_cache_root_from_env_value(" 0 "), None);
        assert_eq!(native_cache_root_from_env_value(""), None);
        assert_eq!(
            native_cache_root_from_env_value("/aos/cache"),
            Some(PathBuf::from("/aos/cache"))
        );

        let mut config = NixEvalConfig::new();
        config.set_aos_nix_cache_env_var("/aos/cache".to_owned());
        assert_eq!(config.native_cache_root(), Some(Path::new("/aos/cache")));
        config.set_aos_nix_cache_env_var("0".to_owned());
        assert_eq!(config.native_cache_root(), None);
    }

    #[test]
    fn eval_config_parses_aos_nix_cache_verify_env_values() {
        let mut config = NixEvalConfig::new();
        assert!(
            !config.native_cache_verify(),
            "value decode verification is off by default"
        );
        config.set_aos_nix_cache_verify_env_var("1");
        assert!(config.native_cache_verify());
        config.set_aos_nix_cache_verify_env_var(" true ");
        assert!(config.native_cache_verify());
        config.set_aos_nix_cache_verify_env_var("0");
        assert!(!config.native_cache_verify());
        config.set_aos_nix_cache_verify_env_var("");
        assert!(!config.native_cache_verify());
    }

    #[test]
    fn eval_config_parses_nix_path_env_values() {
        assert_eq!(
            native_nix_path_entries_from_env_value("nixpkgs=/aos/nixpkgs:/aos/channels"),
            Some(vec![
                NixPathConfigEntry {
                    prefix: "nixpkgs".to_string(),
                    path: "/aos/nixpkgs".to_string(),
                },
                NixPathConfigEntry {
                    prefix: String::new(),
                    path: "/aos/channels".to_string(),
                }
            ])
        );
        assert_eq!(
            native_nix_path_entries_from_env_value("nixpkgs=relative/entry::bare"),
            Some(vec![
                NixPathConfigEntry {
                    prefix: "nixpkgs".to_string(),
                    path: "relative/entry".to_string(),
                },
                NixPathConfigEntry {
                    prefix: String::new(),
                    path: "bare".to_string(),
                }
            ])
        );
        assert_eq!(native_nix_path_entries_from_env_value(""), None);
        assert_eq!(
            native_nix_path_entries_from_env_value("https://cache.example/root"),
            None
        );
        assert_eq!(
            native_nix_path_entries_from_env_value("nixpkgs=flake:nixpkgs"),
            None
        );
        assert_eq!(
            native_nix_path_entries_from_env_value("channel:nixos-unstable"),
            None
        );
        assert_eq!(native_nix_path_entries_from_env_value(":"), None);
        assert_eq!(native_nix_path_entries_from_env_value("::"), None);
    }

    #[test]
    fn eval_config_renders_cpp_nix_option_args() -> Result<()> {
        assert_eq!(NixEvalConfig::new().cli_option_args(), Vec::<String>::new());
        assert_eq!(
            NixEvalConfig::with_current_system("aos-test-target")?.cli_option_args(),
            ["--option", "system", "aos-test-target"]
        );

        let mut config = NixEvalConfig::with_current_system("aos-test-target")?;
        config.set_trace_verbose(true);
        assert_eq!(
            config.cli_option_args(),
            [
                "--option",
                "system",
                "aos-test-target",
                "--option",
                "trace-verbose",
                "true"
            ]
        );
        Ok(())
    }

    #[test]
    fn eval_config_renders_cpp_nix_eval_policy_options() -> Result<()> {
        let mut impure = NixEvalConfig::new();
        impure.set_eval_mode(NixEvalMode::Impure);
        assert_eq!(
            impure.cli_option_args(),
            [
                "--option",
                "pure-eval",
                "false",
                "--option",
                "restrict-eval",
                "false"
            ]
        );

        let mut pure = NixEvalConfig::new();
        pure.set_eval_mode(NixEvalMode::Pure);
        assert_eq!(
            pure.cli_option_args(),
            [
                "--option",
                "pure-eval",
                "true",
                "--option",
                "restrict-eval",
                "false"
            ]
        );

        let mut restricted = NixEvalConfig::new();
        restricted.set_eval_mode(NixEvalMode::Restricted);
        restricted.set_allowed_paths(["/aos/src", "/aos/store"])?;
        restricted.add_allowed_uri("https://cache.example/")?;
        assert_eq!(
            restricted.cli_option_args(),
            [
                "--option",
                "pure-eval",
                "false",
                "--option",
                "restrict-eval",
                "true",
                "--option",
                "allowed-impure-host-deps",
                "/aos/src /aos/store",
                "--option",
                "allowed-uris",
                "https://cache.example/"
            ]
        );
        Ok(())
    }

    #[test]
    fn eval_config_renders_cpp_nix_env_vars() -> Result<()> {
        let mut config =
            NixEvalConfig::with_store_dirs("/aos/store", "/aos/var/nix", "/aos/var/nix/log/nix")?;
        config.clear_nix_path_env();

        assert_eq!(
            config.cli_env_vars(),
            vec![
                ("NIX_STORE_DIR", "/aos/store".to_string()),
                ("NIX_STATE_DIR", "/aos/var/nix".to_string()),
                ("NIX_LOG_DIR", "/aos/var/nix/log/nix".to_string())
            ]
        );
        Ok(())
    }

    #[test]
    fn eval_config_tracks_native_heap_memory_budget() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.clear_heap_memory_budget();

        assert_eq!(config.heap_memory_budget_bytes(), None);
        config.set_heap_memory_budget_bytes(4096)?;
        assert_eq!(config.heap_memory_budget_bytes(), Some(4096));
        config.clear_heap_memory_budget();
        assert_eq!(config.heap_memory_budget_bytes(), None);

        let error = config
            .set_heap_memory_budget_bytes(0)
            .expect_err("zero byte budget is invalid");
        assert!(error.to_string().contains("greater than zero"));
        Ok(())
    }

    #[test]
    fn eval_config_keeps_nix_env_bindings_in_get_env_snapshot() -> Result<()> {
        let mut config =
            NixEvalConfig::with_store_dirs("/aos/store", "/aos/var/nix", "/aos/var/nix/log/nix")?;

        assert_eq!(
            config.eval_env_vars.get(b"NIX_STORE_DIR".as_slice()),
            Some(&b"/aos/store".to_vec())
        );
        assert_eq!(
            config.eval_env_vars.get(b"NIX_STATE_DIR".as_slice()),
            Some(&b"/aos/var/nix".to_vec())
        );
        assert_eq!(
            config.eval_env_vars.get(b"NIX_LOG_DIR".as_slice()),
            Some(&b"/aos/var/nix/log/nix".to_vec())
        );

        config.clear_store_dirs();
        assert_eq!(config.eval_env_vars.get(b"NIX_STORE_DIR".as_slice()), None);
        assert_eq!(config.eval_env_vars.get(b"NIX_STATE_DIR".as_slice()), None);
        assert_eq!(config.eval_env_vars.get(b"NIX_LOG_DIR".as_slice()), None);
        Ok(())
    }

    #[test]
    fn eval_config_applies_get_env_snapshot_and_working_dir_to_cpp_command() -> Result<()> {
        let working_dir = tempfile::tempdir()?;
        let mut config = NixEvalConfig::new();
        config.eval_env_vars.clear();
        config.set_eval_env_var_bytes(b"AOS_ARBITRARY_ENV".to_vec(), b"present".to_vec());
        config.set_eval_env_var_bytes(b"AOS_NIX_NATIVE".to_vec(), b"1".to_vec());
        config.set_eval_env_var_bytes(b"AOS_NIX_NATIVE_VERIFY".to_vec(), b"1".to_vec());
        config.set_eval_env_var_bytes(b"AOS_NIX_MAX_RSS".to_vec(), b"4096".to_vec());
        config.set_nix_path_env("nixpkgs=/aos/nixpkgs");
        config.set_working_dir(working_dir.path())?;

        let mut command = Command::new("nix-instantiate");
        command.env("STALE_COMMAND_ENV", "stale");
        config.apply_cli_env(&mut command);

        assert_eq!(
            command_env_bytes(&command, b"AOS_ARBITRARY_ENV").as_deref(),
            Some(b"present".as_slice())
        );
        assert_eq!(
            command_env_bytes(&command, b"NIX_PATH").as_deref(),
            Some(b"nixpkgs=/aos/nixpkgs".as_slice())
        );
        assert!(!is_evaluator_control_env_var(b"AOS_ARBITRARY_ENV"));
        assert!(is_evaluator_control_env_var(b"AOS_NIX_NATIVE"));
        assert!(is_evaluator_control_env_var(b"AOS_NIX_NATIVE_VERIFY"));
        assert!(is_evaluator_control_env_var(b"AOS_NIX_MAX_RSS"));
        assert_eq!(config.eval_env_vars.get(b"AOS_NIX_NATIVE".as_slice()), None);
        assert_eq!(
            config
                .eval_env_vars
                .get(b"AOS_NIX_NATIVE_VERIFY".as_slice()),
            None
        );
        assert_eq!(
            config.eval_env_vars.get(b"AOS_NIX_MAX_RSS".as_slice()),
            None
        );
        assert_eq!(command_env_bytes(&command, b"AOS_NIX_NATIVE"), None);
        assert_eq!(command_env_bytes(&command, b"AOS_NIX_NATIVE_VERIFY"), None);
        assert_eq!(command_env_bytes(&command, b"AOS_NIX_MAX_RSS"), None);
        assert_eq!(command_env_bytes(&command, b"STALE_COMMAND_ENV"), None);
        assert_eq!(command.get_current_dir(), Some(working_dir.path()));
        Ok(())
    }

    #[test]
    fn eval_config_applies_home_dir_to_cpp_command_and_get_env_snapshot() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.eval_env_vars.clear();
        config.set_home_dir("/home/aos")?;

        assert_eq!(config.home_dir(), Some(Path::new("/home/aos")));
        assert_eq!(
            config.eval_env_vars.get(b"HOME".as_slice()),
            Some(&b"/home/aos".to_vec())
        );

        let mut command = Command::new("nix-instantiate");
        config.apply_cli_env(&mut command);

        assert_eq!(
            command_env_bytes(&command, b"HOME").as_deref(),
            Some(b"/home/aos".as_slice())
        );

        config.clear_home_dir();
        assert_eq!(config.home_dir(), None);
        assert_eq!(config.eval_env_vars.get(b"HOME".as_slice()), None);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn eval_config_applies_non_utf8_get_env_snapshot_to_cpp_command() {
        let mut config = NixEvalConfig::new();
        config.eval_env_vars.clear();
        config.set_eval_env_var_bytes(b"AOS_NON_UTF8_ENV".to_vec(), b"value-\xff".to_vec());

        let mut command = Command::new("nix-instantiate");
        config.apply_cli_env(&mut command);

        assert_eq!(
            command_env_bytes(&command, b"AOS_NON_UTF8_ENV").as_deref(),
            Some(b"value-\xff".as_slice())
        );
    }

    #[test]
    fn eval_config_renders_cpp_nix_path_env_var() {
        let mut config = NixEvalConfig::new();
        config.clear_store_dirs();
        config.set_nix_path_env("nixpkgs=/aos/nixpkgs:/aos/channels");

        assert_eq!(
            config.eval_env_vars.get(b"NIX_PATH".as_slice()),
            Some(&b"nixpkgs=/aos/nixpkgs:/aos/channels".to_vec())
        );
        assert_eq!(
            config.cli_env_vars(),
            vec![("NIX_PATH", "nixpkgs=/aos/nixpkgs:/aos/channels".to_string())]
        );

        config.clear_nix_path_env();
        assert_eq!(config.eval_env_vars.get(b"NIX_PATH".as_slice()), None);
        assert_eq!(config.cli_env_vars(), Vec::<(&'static str, String)>::new());
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_trace_verbose_to_native_options() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);
        config.set_trace_verbose(true);

        let options = tree_walk_options_from_config(&config)?;

        assert!(options.trace_verbose());
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_heap_memory_budget_to_native_options() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);
        config.clear_heap_memory_budget();

        let options = tree_walk_options_from_config(&config)?;
        assert!(!options.heap_tier_b_transition_admission_enabled());

        config.set_heap_memory_budget_bytes(4096)?;

        let options = tree_walk_options_from_config(&config)?;

        assert_eq!(
            options
                .heap_memory_budget()
                .map(|budget| budget.max_resident_bytes()),
            Some(4096)
        );
        assert!(options.heap_tier_b_transition_admission_enabled());
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_eval_policy_to_native_options() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Restricted);
        config.set_allowed_paths(["/aos/src"])?;
        config.set_allowed_uris(["github:", "https://cache.example/"])?;

        let options = tree_walk_options_from_config(&config)?;

        assert_eq!(options.eval_mode(), EvalMode::Restricted);
        assert_eq!(options.allowed_paths(), &[b"/aos/src".to_vec()]);
        assert_eq!(
            options.allowed_uris(),
            &[b"github:".to_vec(), b"https://cache.example/".to_vec()]
        );
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_get_env_snapshot_to_native_options() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);
        config.eval_env_vars.clear();
        config.set_eval_env_var_bytes(b"HOME".to_vec(), b"/home/aos".to_vec());

        let options = tree_walk_options_from_config(&config)?;

        assert_eq!(options.env_var(b"HOME"), Some(b"/home/aos".as_slice()));
        assert_eq!(options.env_var(b"MISSING"), None);
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_path_context_to_native_options() -> Result<()> {
        let working_dir = tempfile::tempdir()?;
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);
        config.set_working_dir(working_dir.path())?;
        config.set_home_dir("/home/aos")?;

        let options = tree_walk_options_from_config(&config)?;

        let expected = path_bytes(working_dir.path());
        assert_eq!(options.search_path_base(), expected.as_slice());
        assert_eq!(options.path_literal_base(), Some(expected.as_slice()));
        assert_eq!(options.home_dir(), Some(b"/home/aos".as_slice()));
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_pure_mode_without_restricted_allowlists() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Pure);
        config.set_allowed_paths(["/aos/src"])?;
        config.set_allowed_uris(["github:"])?;

        let options = tree_walk_options_from_config(&config)?;

        assert_eq!(options.eval_mode(), EvalMode::Pure);
        assert!(options.allowed_paths().is_empty());
        assert!(options.allowed_uris().is_empty());
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_nix_path_to_native_options() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);
        config.set_nix_path_env("nixpkgs=/aos/nixpkgs:/aos/channels");

        let options = tree_walk_options_from_config(&config)?;

        let entries = options.nix_path();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].prefix(), b"nixpkgs");
        assert_eq!(entries[0].path(), b"/aos/nixpkgs");
        assert_eq!(entries[1].prefix(), b"");
        assert_eq!(entries[1].path(), b"/aos/channels");
        assert!(!options.reject_ambient_search_path());
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_rejects_unrepresentable_native_nix_path() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);

        let options = tree_walk_options_from_config(&config)?;
        assert!(options.reject_ambient_search_path());

        config.set_nix_path_env("");
        let options = tree_walk_options_from_config(&config)?;
        assert!(options.reject_ambient_search_path());

        config.set_nix_path_env("nixpkgs=flake:nixpkgs");
        let options = tree_walk_options_from_config(&config)?;
        assert!(options.reject_ambient_search_path());
        assert!(options.nix_path().is_empty());
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_store_dir_to_native_options() -> Result<()> {
        let mut config =
            NixEvalConfig::with_store_dirs("/aos/store", "/aos/var/nix", "/aos/var/nix/log/nix")?;
        config.set_eval_mode(NixEvalMode::Impure);

        let options = tree_walk_options_from_config(&config)?;

        assert_eq!(options.store_dir(), b"/aos/store");
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_native_cache_root_to_cache_options() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);

        let options = tree_walk_options_from_config(&config)?;
        assert_eq!(options.parse_cache_root(), None);
        assert_eq!(options.persist_cache_root(), None);
        assert!(!options.eval_cache_enabled());

        config.set_native_cache_root("/aos/cache")?;

        let options = tree_walk_options_from_config(&config)?;

        assert_eq!(
            options.parse_cache_root(),
            Some(Path::new("/aos/cache/parse"))
        );
        assert_eq!(
            options.persist_cache_root(),
            Some(Path::new("/aos/cache/persist"))
        );
        assert!(options.eval_cache_enabled());

        config.set_aos_nix_cache_env_var("relative/cache".to_owned());
        let options = tree_walk_options_from_config(&config)?;
        assert_eq!(options.parse_cache_root(), None);
        assert_eq!(options.persist_cache_root(), None);
        assert!(!options.eval_cache_enabled());

        config.set_native_cache_root("/aos/cache")?;
        config.set_aos_nix_cache_env_var("0".to_owned());
        let options = tree_walk_options_from_config(&config)?;
        assert_eq!(options.parse_cache_root(), None);
        assert_eq!(options.persist_cache_root(), None);
        assert!(!options.eval_cache_enabled());

        config.set_native_cache_root("/aos/cache")?;
        config.set_aos_nix_cache_env_var("".to_owned());
        let options = tree_walk_options_from_config(&config)?;
        assert_eq!(options.parse_cache_root(), None);
        assert_eq!(options.persist_cache_root(), None);
        assert!(!options.eval_cache_enabled());
        Ok(())
    }

    #[test]
    fn native_mode_defaults_off() {
        assert_eq!(NativeMode::parse(None), NativeMode::Off);
        assert_eq!(NativeMode::parse(Some("")), NativeMode::Off);
        assert_eq!(NativeMode::parse(Some("0")), NativeMode::Off);
        assert_eq!(NativeMode::parse(Some("false")), NativeMode::Off);
        assert_eq!(NativeMode::parse(Some("off")), NativeMode::Off);
        assert_eq!(NativeMode::parse(Some("shdaow")), NativeMode::Off);
    }

    #[test]
    fn native_mode_recognizes_shadow_and_truthy_values() {
        assert_eq!(NativeMode::parse(Some("shadow")), NativeMode::Shadow);
        assert_eq!(NativeMode::parse(Some(" SHADOW ")), NativeMode::Shadow);
        assert_eq!(NativeMode::parse(Some("1")), NativeMode::On);
        assert_eq!(NativeMode::parse(Some("true")), NativeMode::On);
        assert_eq!(NativeMode::parse(Some("yes")), NativeMode::On);
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_verify_mode_defaults_off() {
        assert_eq!(
            parse_native_verify_mode(None),
            (NativeVerifyMode::Off, None)
        );
        assert_eq!(
            parse_native_verify_mode(Some("")),
            (NativeVerifyMode::Off, None)
        );
        assert_eq!(
            parse_native_verify_mode(Some("0")),
            (NativeVerifyMode::Off, None)
        );
        assert_eq!(
            parse_native_verify_mode(Some("false")),
            (NativeVerifyMode::Off, None)
        );
        assert_eq!(
            parse_native_verify_mode(Some("bad")),
            (NativeVerifyMode::Off, Some("bad".to_string()))
        );
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_verify_mode_recognizes_always_values() {
        assert_eq!(
            parse_native_verify_mode(Some("1")),
            (NativeVerifyMode::Always, None)
        );
        assert_eq!(
            parse_native_verify_mode(Some("true")),
            (NativeVerifyMode::Always, None)
        );
        assert_eq!(
            parse_native_verify_mode(Some("always")),
            (NativeVerifyMode::Always, None)
        );
        assert_eq!(
            parse_native_verify_mode(Some(" ON ")),
            (NativeVerifyMode::Always, None)
        );
    }

    #[cfg(not(feature = "native-eval"))]
    #[test]
    fn native_diff_candidate_requires_native_feature() {
        let error = match select_native_diff_candidate_with_config(0, NixEvalConfig::new()) {
            Ok(_) => panic!("native diff selector should require native-eval"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("native-eval feature"));
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_diff_candidate_rejects_ambient_eval_policy() {
        let error = match select_native_diff_candidate_with_config(0, NixEvalConfig::new()) {
            Ok(_) => panic!("raw native candidate should require explicit eval policy"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("explicit evaluation mode"));
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_diff_candidate_does_not_fall_back_to_cli() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);
        let candidate = select_native_diff_candidate_with_config(0, config)?;

        let error = candidate
            .instantiate_expr("1")
            .expect_err("raw native instantiation should reject non-derivations");

        assert!(matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { .. } | NativeEvalError::EvalError { .. })
        ));
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_only_eval_records_authoritative_successes() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);
        let evaluator = NativeOnlyEval::new(0, config)?;
        let before = native_success_stats();

        assert_eq!(evaluator.eval_expr("1 + 1")?, "2");

        let after = native_success_stats();
        assert!(after.expression_evaluations() > before.expression_evaluations());
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_only_eval_reports_strict_json_stats() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);
        config.clear_heap_memory_budget();
        let evaluator = NativeOnlyEval::new(0, config)?;
        let before = native_success_stats();

        let (value, stats) =
            evaluator.eval_expr_with_stats(r#"let f = x: { a = [ x "tier-a" ]; }; in f 1"#)?;

        let stats = stats.expect("native-only evaluator reports strict JSON stats");
        assert_eq!(value, r#"{"a":[1,"tier-a"]}"#);
        assert!(stats.heap_chunks() > 0);
        assert!(stats.heap_mapped_bytes() >= stats.heap_reserved_bytes());
        assert!(stats.heap_reserved_bytes() >= stats.heap_used_bytes());
        assert!(stats.heap_used_bytes() > 0);
        assert!(stats.permanent_heap_chunks() > 0);
        assert!(stats.permanent_heap_mapped_bytes() >= stats.permanent_heap_reserved_bytes());
        assert!(stats.permanent_heap_reserved_bytes() >= stats.permanent_heap_used_bytes());
        assert!(stats.permanent_heap_used_bytes() > 0);
        assert_eq!(stats.gc_bytes(), 0);
        assert_eq!(stats.gc_pause_us(), 0);
        assert_eq!(stats.tier_promotions(), 0);
        assert_eq!(stats.deopts(), 0);
        assert_eq!(stats.heap_tier_b_admission_worker_records(), 0);
        assert_eq!(stats.heap_tier_b_admission_permanent_shared_records(), 0);
        assert_eq!(stats.heap_tier_b_admission_generation_rewrites(), 0);

        let after = native_success_stats();
        assert!(after.expression_evaluations() > before.expression_evaluations());
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_only_eval_reports_heap_tier_b_admission_strict_json_stats() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Impure);
        config.set_heap_memory_budget_bytes(1)?;
        let evaluator = NativeOnlyEval::new(0, config)?;

        let (value, stats) =
            evaluator.eval_expr_with_stats(r#"let f = x: { a = [ x "tier-b" ]; }; in f 1"#)?;

        let stats = stats.expect("native-only evaluator reports strict JSON stats");
        assert_eq!(value, r#"{"a":[1,"tier-b"]}"#);
        assert!(stats.heap_tier_b_admission_worker_records() > 0);
        assert_eq!(
            stats.heap_tier_b_admission_generation_rewrites(),
            stats.heap_tier_b_admission_worker_records()
        );

        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn aos_nix_cache_zero_bypasses_native_closure_cache_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = root.path().join("store");
        let state = root.path().join("state");
        let log = root.path().join("log");
        let disabled_cache_root = root.path().join("cache-disabled-file");
        fs::write(&disabled_cache_root, b"not a cache directory")?;
        let source = r#"derivationStrict {
             name = "cache-zero";
             system = builtins.currentSystem;
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             args = [ builtins.currentSystem ];
           }"#;

        let mut baseline_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        baseline_config.set_eval_mode(NixEvalMode::Impure);
        baseline_config.set_current_system("x86_64-linux")?;
        baseline_config.clear_native_cache_root();
        let baseline_evaluator = NativeOnlyEval::new(0, baseline_config)?;
        let baseline = baseline_evaluator.native.instantiate_expr_closure(source)?;

        let mut disabled_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        disabled_config.set_eval_mode(NixEvalMode::Impure);
        disabled_config.set_current_system("x86_64-linux")?;
        disabled_config.set_native_cache_root(&disabled_cache_root)?;
        disabled_config.set_aos_nix_cache_env_var("0".to_owned());
        assert_eq!(disabled_config.native_cache_root(), None);
        let disabled_options = tree_walk_options_from_config(&disabled_config)?;
        assert_eq!(disabled_options.parse_cache_root(), None);
        assert_eq!(disabled_options.persist_cache_root(), None);
        assert!(!disabled_options.eval_cache_enabled());
        let disabled_evaluator = NativeOnlyEval::new(0, disabled_config)?;
        let (disabled, disabled_stats) = disabled_evaluator
            .native
            .instantiate_expr_closure_with_stats(source)?;
        assert_no_incremental_cache_stats(
            &disabled_stats,
            "AOS_NIX_CACHE=0 raw expression closure over stale file cache root",
        );

        let (baseline_root, baseline_drvs) = baseline.into_parts();
        let (disabled_root, disabled_drvs) = disabled.into_parts();
        assert_eq!(disabled_root, baseline_root);
        assert_eq!(disabled_drvs, baseline_drvs);
        assert!(
            disabled_cache_root.is_file(),
            "AOS_NIX_CACHE=0 should not touch the stale cache-root path"
        );
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn aos_nix_cache_zero_bypasses_populated_native_closure_cache_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = root.path().join("store");
        let state = root.path().join("state");
        let log = root.path().join("log");
        let cache_root = root.path().join("cache");
        let source = r#"derivationStrict {
             name = "cache-zero-populated";
             system = builtins.currentSystem;
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             args = [ builtins.currentSystem ];
           }"#;

        let mut baseline_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        baseline_config.set_eval_mode(NixEvalMode::Impure);
        baseline_config.set_current_system("x86_64-linux")?;
        baseline_config.clear_native_cache_root();
        let baseline_evaluator = NativeOnlyEval::new(0, baseline_config)?;
        let baseline = baseline_evaluator.native.instantiate_expr_closure(source)?;

        let mut seed_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        seed_config.set_eval_mode(NixEvalMode::Impure);
        seed_config.set_current_system("x86_64-linux")?;
        seed_config.set_native_cache_root(&cache_root)?;
        let first_seed = NativeOnlyEval::new(0, seed_config.clone())?
            .native
            .instantiate_expr_closure(source)?;
        let materialized_seed = NativeOnlyEval::new(0, seed_config)?
            .native
            .instantiate_expr_closure(source)?;
        assert_eq!(first_seed, baseline);
        assert_eq!(materialized_seed, baseline);

        let persist_root = cache_root.join("persist");
        assert_persistent_force_cache_payload_entries(&persist_root)?;
        let cache_before = snapshot_regular_file_tree(&cache_root)?;
        assert!(
            !cache_before.is_empty(),
            "cache-enabled seed should populate the native cache root"
        );

        let mut disabled_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        disabled_config.set_eval_mode(NixEvalMode::Impure);
        disabled_config.set_current_system("x86_64-linux")?;
        disabled_config.set_native_cache_root(&cache_root)?;
        disabled_config.set_aos_nix_cache_env_var("0".to_owned());
        assert_eq!(disabled_config.native_cache_root(), None);
        let disabled_options = tree_walk_options_from_config(&disabled_config)?;
        assert_eq!(disabled_options.parse_cache_root(), None);
        assert_eq!(disabled_options.persist_cache_root(), None);
        assert!(!disabled_options.eval_cache_enabled());
        let disabled_evaluator = NativeOnlyEval::new(0, disabled_config)?;
        let (disabled, disabled_stats) = disabled_evaluator
            .native
            .instantiate_expr_closure_with_stats(source)?;
        assert_no_incremental_cache_stats(
            &disabled_stats,
            "AOS_NIX_CACHE=0 raw expression closure over populated cache root",
        );

        let (baseline_root, baseline_drvs) = baseline.into_parts();
        let (disabled_root, disabled_drvs) = disabled.into_parts();
        assert_eq!(disabled_root, baseline_root);
        assert_eq!(disabled_drvs, baseline_drvs);
        assert_eq!(
            snapshot_regular_file_tree(&cache_root)?,
            cache_before,
            "AOS_NIX_CACHE=0 should not mutate the populated cache-root path"
        );
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn aos_nix_cache_zero_bypasses_populated_native_eval_expr_cache_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = root.path().join("store");
        let state = root.path().join("state");
        let log = root.path().join("log");
        let cache_root = root.path().join("cache");
        let source = "let attrs = { payload = \"eval expr cache payload\"; }; in attrs.payload";

        let mut baseline_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        baseline_config.set_eval_mode(NixEvalMode::Impure);
        baseline_config.clear_native_cache_root();
        let baseline_evaluator = NativeOnlyEval::new(0, baseline_config)?;
        let baseline = baseline_evaluator.native.eval_expr(&source)?;
        assert_eq!(baseline, "\"eval expr cache payload\"");

        let mut seed_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        seed_config.set_eval_mode(NixEvalMode::Impure);
        seed_config.set_native_cache_root(&cache_root)?;
        let first_seed = NativeOnlyEval::new(0, seed_config.clone())?
            .native
            .eval_expr(&source)?;
        let materialized_seed = NativeOnlyEval::new(0, seed_config)?
            .native
            .eval_expr(&source)?;
        assert_eq!(first_seed, baseline);
        assert_eq!(materialized_seed, baseline);

        let persist_root = cache_root.join("persist");
        assert_persistent_force_cache_payload_entries(&persist_root)?;
        let cache_before = snapshot_regular_file_tree(&cache_root)?;
        assert!(
            !cache_before.is_empty(),
            "cache-enabled eval_expr seed should populate the native cache root"
        );

        let mut disabled_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        disabled_config.set_eval_mode(NixEvalMode::Impure);
        disabled_config.set_native_cache_root(&cache_root)?;
        disabled_config.set_aos_nix_cache_env_var("0".to_owned());
        assert_eq!(disabled_config.native_cache_root(), None);
        let disabled_options = tree_walk_options_from_config(&disabled_config)?;
        assert_eq!(disabled_options.parse_cache_root(), None);
        assert_eq!(disabled_options.persist_cache_root(), None);
        assert!(!disabled_options.eval_cache_enabled());
        let disabled_evaluator = NativeOnlyEval::new(0, disabled_config)?;
        let (disabled, disabled_stats) = disabled_evaluator.native.eval_expr_with_stats(source)?;
        assert_no_incremental_cache_stats(
            &disabled_stats,
            "AOS_NIX_CACHE=0 strict JSON eval over populated cache root",
        );

        assert_eq!(disabled, baseline);
        assert_eq!(
            snapshot_regular_file_tree(&cache_root)?,
            cache_before,
            "AOS_NIX_CACHE=0 should not mutate populated eval_expr cache-root regular-file paths or bytes"
        );
        Ok(())
    }

    #[cfg(all(feature = "native-eval", unix))]
    #[test]
    fn aos_nix_cache_zero_leaves_non_file_cache_roots_untouched() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = root.path().join("store");
        let state = root.path().join("state");
        let log = root.path().join("log");
        let source = r#"derivationStrict {
             name = "cache-zero-non-file-roots";
             system = builtins.currentSystem;
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             args = [ builtins.currentSystem ];
           }"#;

        let mut baseline_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        baseline_config.set_eval_mode(NixEvalMode::Impure);
        baseline_config.set_current_system("x86_64-linux")?;
        baseline_config.clear_native_cache_root();
        let baseline_evaluator = NativeOnlyEval::new(0, baseline_config)?;
        let baseline = baseline_evaluator.native.instantiate_expr_closure(source)?;

        let directory_root = root.path().join("cache-directory-only");
        fs::create_dir_all(directory_root.join("parse/entry"))?;
        fs::create_dir_all(directory_root.join("persist/nodes"))?;
        let directory_before = snapshot_cache_root_tree(&directory_root)?;

        let symlink_target = root.path().join("cache-symlink-target");
        fs::create_dir_all(symlink_target.join("persist/values"))?;
        fs::write(symlink_target.join("sentinel"), b"target payload")?;
        let symlink_root = root.path().join("cache-symlink");
        std::os::unix::fs::symlink(&symlink_target, &symlink_root)?;
        let symlink_before = snapshot_cache_root_tree(&symlink_root)?;
        let symlink_target_before = snapshot_cache_root_tree(&symlink_target)?;

        let stale_metadata_root = root.path().join("cache-stale-metadata");
        fs::create_dir_all(stale_metadata_root.join("parse"))?;
        fs::create_dir_all(stale_metadata_root.join("persist/nodes"))?;
        fs::write(
            stale_metadata_root.join("schema.toml"),
            b"format = \"aos-nix-cache\"\nversion = 999\n",
        )?;
        fs::write(
            stale_metadata_root.join("persist/schema.toml"),
            b"format = \"aos-nix-persist-cache\"\nversion = 999\n",
        )?;
        let stale_metadata_before = snapshot_cache_root_tree(&stale_metadata_root)?;

        for cache_root in [&directory_root, &symlink_root, &stale_metadata_root] {
            let mut disabled_config = NixEvalConfig::with_store_dirs(
                store.to_string_lossy().into_owned(),
                state.to_string_lossy().into_owned(),
                log.to_string_lossy().into_owned(),
            )?;
            disabled_config.set_eval_mode(NixEvalMode::Impure);
            disabled_config.set_current_system("x86_64-linux")?;
            disabled_config.set_native_cache_root(cache_root)?;
            disabled_config.set_aos_nix_cache_env_var("0".to_owned());
            assert_eq!(disabled_config.native_cache_root(), None);
            let disabled_options = tree_walk_options_from_config(&disabled_config)?;
            assert_eq!(disabled_options.parse_cache_root(), None);
            assert_eq!(disabled_options.persist_cache_root(), None);
            assert!(!disabled_options.eval_cache_enabled());
            let disabled_evaluator = NativeOnlyEval::new(0, disabled_config)?;
            let (disabled, disabled_stats) = disabled_evaluator
                .native
                .instantiate_expr_closure_with_stats(source)?;
            assert_no_incremental_cache_stats(
                &disabled_stats,
                "AOS_NIX_CACHE=0 raw expression closure over non-file cache root",
            );

            assert_eq!(disabled, baseline);
        }

        assert_eq!(
            snapshot_cache_root_tree(&directory_root)?,
            directory_before,
            "AOS_NIX_CACHE=0 should not mutate directory-only cache roots"
        );
        assert_eq!(
            snapshot_cache_root_tree(&symlink_root)?,
            symlink_before,
            "AOS_NIX_CACHE=0 should not rewrite cache-root symlinks"
        );
        assert_eq!(
            snapshot_cache_root_tree(&symlink_target)?,
            symlink_target_before,
            "AOS_NIX_CACHE=0 should not touch symlinked cache-root targets"
        );
        assert_eq!(
            snapshot_cache_root_tree(&stale_metadata_root)?,
            stale_metadata_before,
            "AOS_NIX_CACHE=0 should not mutate stale metadata-shaped cache roots"
        );
        Ok(())
    }

    #[cfg(all(feature = "native-eval", unix))]
    #[test]
    fn aos_nix_cache_zero_ignores_inaccessible_cache_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = root.path().join("store");
        let state = root.path().join("state");
        let log = root.path().join("log");
        let source = r#"derivationStrict {
             name = "cache-zero-inaccessible-root";
             system = builtins.currentSystem;
             builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             args = [ builtins.currentSystem ];
           }"#;

        let mut baseline_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        baseline_config.set_eval_mode(NixEvalMode::Impure);
        baseline_config.set_current_system("x86_64-linux")?;
        baseline_config.clear_native_cache_root();
        let baseline_evaluator = NativeOnlyEval::new(0, baseline_config)?;
        let baseline = baseline_evaluator.native.instantiate_expr_closure(source)?;

        let blocked_parent = root.path().join("blocked-cache-parent");
        let cache_root = blocked_parent.join("cache");
        fs::create_dir_all(cache_root.join("parse/entry"))?;
        fs::create_dir_all(cache_root.join("persist/nodes"))?;
        fs::write(cache_root.join("sentinel"), b"must remain untouched")?;
        let cache_before = snapshot_cache_root_tree(&cache_root)?;
        let restore_permissions = PermissionRestoreGuard::new(&blocked_parent)?;
        let mut blocked_permissions = fs::metadata(&blocked_parent)?.permissions();
        blocked_permissions.set_mode(0o000);
        fs::set_permissions(&blocked_parent, blocked_permissions)?;
        match fs::read_dir(&cache_root) {
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => anyhow::bail!(
                "inaccessible cache-root preflight expected PermissionDenied, got {error}"
            ),
            Ok(_) => anyhow::bail!("inaccessible cache-root preflight left cache root readable"),
        }

        let disabled_result = (|| -> Result<(NativeDrvClosure, aos_nix::eval::EvalStats)> {
            let mut disabled_config = NixEvalConfig::with_store_dirs(
                store.to_string_lossy().into_owned(),
                state.to_string_lossy().into_owned(),
                log.to_string_lossy().into_owned(),
            )?;
            disabled_config.set_eval_mode(NixEvalMode::Impure);
            disabled_config.set_current_system("x86_64-linux")?;
            disabled_config.set_native_cache_root(&cache_root)?;
            disabled_config.set_aos_nix_cache_env_var("0".to_owned());
            anyhow::ensure!(
                disabled_config.native_cache_root().is_none(),
                "AOS_NIX_CACHE=0 should clear inaccessible native cache root"
            );
            let disabled_options = tree_walk_options_from_config(&disabled_config)?;
            anyhow::ensure!(
                disabled_options.parse_cache_root().is_none(),
                "AOS_NIX_CACHE=0 should clear parse cache root"
            );
            anyhow::ensure!(
                disabled_options.persist_cache_root().is_none(),
                "AOS_NIX_CACHE=0 should clear persist cache root"
            );
            anyhow::ensure!(
                !disabled_options.eval_cache_enabled(),
                "AOS_NIX_CACHE=0 should disable eval cache"
            );
            let disabled_evaluator = NativeOnlyEval::new(0, disabled_config)?;
            disabled_evaluator
                .native
                .instantiate_expr_closure_with_stats(source)
        })();

        restore_permissions.restore()?;
        let (disabled, disabled_stats) = disabled_result?;
        assert_no_incremental_cache_stats(
            &disabled_stats,
            "AOS_NIX_CACHE=0 raw expression closure over inaccessible cache root",
        );

        assert_eq!(disabled, baseline);
        assert_eq!(
            snapshot_cache_root_tree(&cache_root)?,
            cache_before,
            "AOS_NIX_CACHE=0 should not require access to or mutate inaccessible cache roots"
        );
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn aos_nix_cache_zero_bypasses_file_backed_native_closure_cache_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = root.path().join("store");
        let state = root.path().join("state");
        let log = root.path().join("log");
        let source_dir = root.path().join("src");
        fs::create_dir_all(&source_dir)?;
        let file = source_dir.join("default.nix");
        fs::write(
            &file,
            r#"{
              pkgs.hello = derivationStrict {
                name = "cache-zero-file";
                system = builtins.currentSystem;
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                args = [ builtins.currentSystem ];
              };
            }"#,
        )?;
        let disabled_cache_root = root.path().join("cache-disabled-file");
        fs::write(&disabled_cache_root, b"not a cache directory")?;

        let mut baseline_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        baseline_config.set_eval_mode(NixEvalMode::Impure);
        baseline_config.set_current_system("x86_64-linux")?;
        baseline_config.clear_native_cache_root();
        let baseline_evaluator = NativeOnlyEval::new(0, baseline_config)?;
        let baseline = baseline_evaluator
            .instantiate_closure(&file, "pkgs.hello")?
            .expect("native-only evaluator returns file closures");

        let mut disabled_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        disabled_config.set_eval_mode(NixEvalMode::Impure);
        disabled_config.set_current_system("x86_64-linux")?;
        disabled_config.set_native_cache_root(&disabled_cache_root)?;
        disabled_config.set_aos_nix_cache_env_var("0".to_owned());
        assert_eq!(disabled_config.native_cache_root(), None);
        let disabled_options = tree_walk_options_from_config(&disabled_config)?;
        assert_eq!(disabled_options.parse_cache_root(), None);
        assert_eq!(disabled_options.persist_cache_root(), None);
        assert!(!disabled_options.eval_cache_enabled());
        let disabled_evaluator = NativeOnlyEval::new(0, disabled_config)?;
        let (disabled, disabled_stats) =
            disabled_evaluator.instantiate_closure_with_stats(&file, "pkgs.hello")?;
        assert_no_incremental_cache_stats(
            &disabled_stats,
            "AOS_NIX_CACHE=0 file-backed closure over stale file cache root",
        );

        let (baseline_root, baseline_drvs) = baseline.into_parts();
        let (disabled_root, disabled_drvs) = disabled.into_parts();
        assert_eq!(disabled_root, baseline_root);
        assert_eq!(disabled_drvs, baseline_drvs);
        assert!(
            disabled_cache_root.is_file(),
            "AOS_NIX_CACHE=0 should not touch the stale file-backed cache-root path"
        );
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn aos_nix_cache_zero_bypasses_populated_file_backed_native_closure_cache_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = root.path().join("store");
        let state = root.path().join("state");
        let log = root.path().join("log");
        let cache_root = root.path().join("cache");
        let source_dir = root.path().join("src");
        fs::create_dir_all(&source_dir)?;
        let file = source_dir.join("default.nix");
        fs::write(
            &file,
            r#"{
              pkgs.hello = derivationStrict {
                name = "cache-zero-populated-file";
                system = builtins.currentSystem;
                builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                args = [ builtins.currentSystem ];
              };
            }"#,
        )?;

        let mut baseline_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        baseline_config.set_eval_mode(NixEvalMode::Impure);
        baseline_config.set_current_system("x86_64-linux")?;
        baseline_config.clear_native_cache_root();
        let baseline_evaluator = NativeOnlyEval::new(0, baseline_config)?;
        let baseline = baseline_evaluator
            .instantiate_closure(&file, "pkgs.hello")?
            .expect("native-only evaluator returns file closures");

        let mut seed_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        seed_config.set_eval_mode(NixEvalMode::Impure);
        seed_config.set_current_system("x86_64-linux")?;
        seed_config.set_native_cache_root(&cache_root)?;
        let first_seed = NativeOnlyEval::new(0, seed_config.clone())?
            .instantiate_closure(&file, "pkgs.hello")?
            .expect("native-only evaluator returns seeded file closures");
        let materialized_seed = NativeOnlyEval::new(0, seed_config)?
            .instantiate_closure(&file, "pkgs.hello")?
            .expect("native-only evaluator returns materialized file closures");
        assert_eq!(first_seed, baseline);
        assert_eq!(materialized_seed, baseline);

        let persist_root = cache_root.join("persist");
        assert_persistent_force_cache_payload_entries(&persist_root)?;
        let cache_before = snapshot_regular_file_tree(&cache_root)?;
        assert!(
            !cache_before.is_empty(),
            "cache-enabled file seed should populate the native cache root"
        );

        let mut disabled_config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        disabled_config.set_eval_mode(NixEvalMode::Impure);
        disabled_config.set_current_system("x86_64-linux")?;
        disabled_config.set_native_cache_root(&cache_root)?;
        disabled_config.set_aos_nix_cache_env_var("0".to_owned());
        assert_eq!(disabled_config.native_cache_root(), None);
        let disabled_options = tree_walk_options_from_config(&disabled_config)?;
        assert_eq!(disabled_options.parse_cache_root(), None);
        assert_eq!(disabled_options.persist_cache_root(), None);
        assert!(!disabled_options.eval_cache_enabled());
        let disabled_evaluator = NativeOnlyEval::new(0, disabled_config)?;
        let (disabled, disabled_stats) =
            disabled_evaluator.instantiate_closure_with_stats(&file, "pkgs.hello")?;
        assert_no_incremental_cache_stats(
            &disabled_stats,
            "AOS_NIX_CACHE=0 file-backed closure over populated cache root",
        );

        let (baseline_root, baseline_drvs) = baseline.into_parts();
        let (disabled_root, disabled_drvs) = disabled.into_parts();
        assert_eq!(disabled_root, baseline_root);
        assert_eq!(disabled_drvs, baseline_drvs);
        assert_eq!(
            snapshot_regular_file_tree(&cache_root)?,
            cache_before,
            "AOS_NIX_CACHE=0 should not mutate the populated file-backed cache-root path"
        );
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_fallback_eval_returns_native_instantiation_success() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = root.path().join("store");
        let state = root.path().join("state");
        let log = root.path().join("log");
        let mut config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
        config.set_eval_mode(NixEvalMode::Impure);
        let evaluator = NativeFallbackEval::new(0, config)?;
        let before = native_success_stats();

        let path = evaluator.instantiate_expr(
            r#"derivationStrict {
                 name = "base";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }"#,
        )?;

        assert!(path.starts_with(&store), "{}", path.display());
        assert!(path.to_string_lossy().ends_with("-base.drv"));
        assert!(path.exists(), "{}", path.display());
        let after = native_success_stats();
        assert!(after.expression_instantiations() > before.expression_instantiations());
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_fallback_decision_uses_native_error_taxonomy() {
        let unsupported: anyhow::Error = NativeEvalError::unsupported("missing primop").into();
        assert_eq!(
            native_cli_fallback_reason(&unsupported),
            Some(NativeCliFallbackReason::Unsupported)
        );

        let internal: anyhow::Error = NativeEvalError::Internal {
            message: "bug".to_string(),
        }
        .into();
        assert_eq!(
            native_cli_fallback_reason(&internal),
            Some(NativeCliFallbackReason::Internal)
        );

        let eval_error: anyhow::Error = NativeEvalError::EvalError {
            message: "type error".to_string(),
        }
        .into();
        assert_eq!(native_cli_fallback_reason(&eval_error), None);

        let other = anyhow::anyhow!("non-native error");
        assert_eq!(native_cli_fallback_reason(&other), None);
    }

    #[test]
    fn native_fallback_stats_total_sums_reason_counts() {
        let stats = NativeFallbackStats {
            unsupported: 2,
            internal: 3,
        };

        assert_eq!(stats.unsupported(), 2);
        assert_eq!(stats.internal(), 3);
        assert_eq!(stats.total(), 5);
    }

    #[test]
    fn native_success_stats_total_sums_operation_counts() {
        let stats = NativeSuccessStats {
            file_instantiations: 2,
            expression_instantiations: 3,
            expression_evaluations: 5,
        };

        assert_eq!(stats.file_instantiations(), 2);
        assert_eq!(stats.expression_instantiations(), 3);
        assert_eq!(stats.expression_evaluations(), 5);
        assert_eq!(stats.total(), 10);
    }

    #[test]
    fn native_shadow_stats_total_sums_comparison_counts() {
        let stats = NativeShadowStats {
            drv_matches: 2,
            drv_divergences: 3,
            drv_incomplete: 5,
            expression_matches: 7,
            expression_divergences: 11,
            expression_incomplete: 13,
        };

        assert_eq!(stats.drv_matches(), 2);
        assert_eq!(stats.drv_divergences(), 3);
        assert_eq!(stats.drv_incomplete(), 5);
        assert_eq!(stats.expression_matches(), 7);
        assert_eq!(stats.expression_divergences(), 11);
        assert_eq!(stats.expression_incomplete(), 13);
        assert_eq!(stats.matches(), 9);
        assert_eq!(stats.divergences(), 14);
        assert_eq!(stats.incomplete(), 18);
        assert_eq!(stats.total(), 41);
    }

    #[test]
    fn native_verify_stats_total_sums_comparison_counts() {
        let stats = NativeVerifyStats {
            drv_matches: 2,
            drv_divergences: 3,
            drv_incomplete: 5,
            expression_matches: 7,
            expression_divergences: 11,
            expression_incomplete: 13,
        };

        assert_eq!(stats.drv_matches(), 2);
        assert_eq!(stats.drv_divergences(), 3);
        assert_eq!(stats.drv_incomplete(), 5);
        assert_eq!(stats.expression_matches(), 7);
        assert_eq!(stats.expression_divergences(), 11);
        assert_eq!(stats.expression_incomplete(), 13);
        assert_eq!(stats.matches(), 9);
        assert_eq!(stats.divergences(), 14);
        assert_eq!(stats.incomplete(), 18);
        assert_eq!(stats.total(), 41);
    }

    #[test]
    fn native_eval_stats_groups_success_and_fallback_counts() {
        let stats = NativeEvalStats {
            successes: NativeSuccessStats {
                file_instantiations: 1,
                expression_instantiations: 2,
                expression_evaluations: 3,
            },
            fallbacks: NativeFallbackStats {
                unsupported: 4,
                internal: 5,
            },
            shadow: NativeShadowStats {
                drv_matches: 6,
                drv_divergences: 7,
                drv_incomplete: 8,
                expression_matches: 9,
                expression_divergences: 10,
                expression_incomplete: 11,
            },
            verify: NativeVerifyStats {
                drv_matches: 12,
                drv_divergences: 13,
                drv_incomplete: 14,
                expression_matches: 15,
                expression_divergences: 16,
                expression_incomplete: 17,
            },
        };

        assert_eq!(stats.successes().total(), 6);
        assert_eq!(stats.fallbacks().total(), 9);
        assert_eq!(stats.shadow().total(), 51);
        assert_eq!(stats.verify().total(), 87);
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_success_recording_counts_by_operation() {
        let before = native_success_stats();

        let file_after = record_native_eval_success(NativeSuccessOperation::FileInstantiation);
        assert!(file_after > before.file_instantiations());
        let file_stats = native_success_stats();
        assert!(file_stats.file_instantiations() >= file_after);

        let instantiation_after =
            record_native_eval_success(NativeSuccessOperation::ExpressionInstantiation);
        assert!(instantiation_after > file_stats.expression_instantiations());
        let instantiation_stats = native_success_stats();
        assert!(instantiation_stats.expression_instantiations() >= instantiation_after);

        let evaluation_after =
            record_native_eval_success(NativeSuccessOperation::ExpressionEvaluation);
        assert!(evaluation_after > instantiation_stats.expression_evaluations());
        let evaluation_stats = native_eval_stats();
        assert!(evaluation_stats.successes().expression_evaluations() >= evaluation_after);
        assert!(evaluation_stats.successes().total() >= evaluation_after);
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_shadow_recording_counts_by_operation_and_outcome() {
        let before = native_shadow_stats();

        let drv_match = record_native_shadow_result(
            NativeShadowOperation::DrvClosure,
            NativeShadowOutcome::Match,
        );
        assert!(drv_match > before.drv_matches());
        let after_drv_match = native_shadow_stats();
        assert!(after_drv_match.drv_matches() >= drv_match);

        let drv_divergence = record_native_shadow_result(
            NativeShadowOperation::DrvClosure,
            NativeShadowOutcome::Divergence,
        );
        assert!(drv_divergence > after_drv_match.drv_divergences());
        let after_drv_divergence = native_shadow_stats();
        assert!(after_drv_divergence.drv_divergences() >= drv_divergence);

        let drv_incomplete = record_native_shadow_result(
            NativeShadowOperation::DrvClosure,
            NativeShadowOutcome::Incomplete,
        );
        assert!(drv_incomplete > after_drv_divergence.drv_incomplete());
        let after_drv_incomplete = native_shadow_stats();
        assert!(after_drv_incomplete.drv_incomplete() >= drv_incomplete);

        let expression_match = record_native_shadow_result(
            NativeShadowOperation::ExpressionEvaluation,
            NativeShadowOutcome::Match,
        );
        assert!(expression_match > after_drv_incomplete.expression_matches());
        let after_expression_match = native_shadow_stats();
        assert!(after_expression_match.expression_matches() >= expression_match);

        let expression_divergence = record_native_shadow_result(
            NativeShadowOperation::ExpressionEvaluation,
            NativeShadowOutcome::Divergence,
        );
        assert!(expression_divergence > after_expression_match.expression_divergences());
        let after_expression_divergence = native_shadow_stats();
        assert!(after_expression_divergence.expression_divergences() >= expression_divergence);

        let expression_incomplete = record_native_shadow_result(
            NativeShadowOperation::ExpressionEvaluation,
            NativeShadowOutcome::Incomplete,
        );
        assert!(expression_incomplete > after_expression_divergence.expression_incomplete());
        let stats = native_eval_stats();
        assert!(stats.shadow().expression_incomplete() >= expression_incomplete);
        assert!(stats.shadow().total() >= expression_incomplete);
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_verify_recording_counts_by_operation_and_outcome() {
        let before = native_verify_stats();

        let drv_match = record_native_verify_result(
            NativeVerifyOperation::DrvClosure,
            NativeVerifyOutcome::Match,
        );
        assert!(drv_match > before.drv_matches());
        let after_drv_match = native_verify_stats();
        assert!(after_drv_match.drv_matches() >= drv_match);

        let drv_divergence = record_native_verify_result(
            NativeVerifyOperation::DrvClosure,
            NativeVerifyOutcome::Divergence,
        );
        assert!(drv_divergence > after_drv_match.drv_divergences());
        let after_drv_divergence = native_verify_stats();
        assert!(after_drv_divergence.drv_divergences() >= drv_divergence);

        let drv_incomplete = record_native_verify_result(
            NativeVerifyOperation::DrvClosure,
            NativeVerifyOutcome::Incomplete,
        );
        assert!(drv_incomplete > after_drv_divergence.drv_incomplete());
        let after_drv_incomplete = native_verify_stats();
        assert!(after_drv_incomplete.drv_incomplete() >= drv_incomplete);

        let expression_match = record_native_verify_result(
            NativeVerifyOperation::ExpressionEvaluation,
            NativeVerifyOutcome::Match,
        );
        assert!(expression_match > after_drv_incomplete.expression_matches());
        let after_expression_match = native_verify_stats();
        assert!(after_expression_match.expression_matches() >= expression_match);

        let expression_divergence = record_native_verify_result(
            NativeVerifyOperation::ExpressionEvaluation,
            NativeVerifyOutcome::Divergence,
        );
        assert!(expression_divergence > after_expression_match.expression_divergences());
        let after_expression_divergence = native_verify_stats();
        assert!(after_expression_divergence.expression_divergences() >= expression_divergence);

        let expression_incomplete = record_native_verify_result(
            NativeVerifyOperation::ExpressionEvaluation,
            NativeVerifyOutcome::Incomplete,
        );
        assert!(expression_incomplete > after_expression_divergence.expression_incomplete());
        let stats = native_eval_stats();
        assert!(stats.verify().expression_incomplete() >= expression_incomplete);
        assert!(stats.verify().total() >= expression_incomplete);
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_fallback_recording_counts_by_reason() {
        let before = native_fallback_stats();

        let unsupported_after = record_native_cli_fallback(NativeCliFallbackReason::Unsupported);
        assert!(unsupported_after > before.unsupported());
        let unsupported_stats = native_fallback_stats();
        assert!(unsupported_stats.unsupported() >= unsupported_after);
        assert!(unsupported_stats.internal() >= before.internal());

        let internal_after = record_native_cli_fallback(NativeCliFallbackReason::Internal);
        assert!(internal_after > unsupported_stats.internal());
        let internal_stats = native_fallback_stats();
        assert!(internal_stats.internal() >= internal_after);
        assert!(internal_stats.total() >= unsupported_after.saturating_add(internal_after));
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_fallback_warning_records_reason_and_counter() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = FallbackWarningSubscriber {
            events: Arc::clone(&events),
        };
        let dispatch = tracing::Dispatch::new(subscriber);
        let before = native_fallback_stats();
        let error: anyhow::Error = NativeEvalError::unsupported("missing primop").into();

        tracing::dispatcher::with_default(&dispatch, || {
            warn_native_cli_fallback(&error, NativeCliFallbackReason::Unsupported);
        });

        let after = native_fallback_stats();
        assert!(after.unsupported() > before.unsupported());
        let events = events.lock().expect("recorded fallback events lock");
        assert!(events.iter().any(|(level, _)| *level == Level::WARN));
        let logged = events
            .iter()
            .map(|(_, event)| event.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            logged.contains("native eval fell back to nix-cli"),
            "{logged}"
        );
        assert!(logged.contains("error=native Nix evaluator does not yet support missing primop"));
        assert!(logged.contains("evaluator=aos-nix"), "{logged}");
        assert!(logged.contains("fallback_evaluator=nix-cli"), "{logged}");
        assert!(logged.contains("fallback_reason=Unsupported"), "{logged}");
        assert!(logged.contains("fallback_count="), "{logged}");
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn shadow_drv_closure_comparison_counts_divergences() {
        let root = PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv");
        let shared = PathBuf::from("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-input.drv");
        let fallback_only = PathBuf::from("/nix/store/cccccccccccccccccccccccccccccccc-old.drv");
        let native_only = PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-new.drv");

        let fallback = DrvClosure::new(root.clone(), {
            let mut drvs = BTreeMap::new();
            drvs.insert(root.clone(), b"root".to_vec());
            drvs.insert(shared.clone(), b"same".to_vec());
            drvs.insert(fallback_only, b"fallback".to_vec());
            drvs
        });
        let matching = DrvClosure::new(root.clone(), fallback.drvs().clone());
        assert_eq!(
            compare_shadow_drv_closure(&fallback, &matching, "file instantiation", None, None),
            0
        );

        let native = DrvClosure::new(
            PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-root.drv"),
            {
                let mut drvs = BTreeMap::new();
                drvs.insert(root, b"different-root-bytes".to_vec());
                drvs.insert(shared, b"same".to_vec());
                drvs.insert(native_only, b"native".to_vec());
                drvs
            },
        );

        assert_eq!(
            compare_shadow_drv_closure(&fallback, &native, "file instantiation", None, None),
            4
        );
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn shadow_drv_closure_divergence_logs_request_context() {
        let root = PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv");
        let fallback = DrvClosure::new(root.clone(), {
            let mut drvs = BTreeMap::new();
            drvs.insert(root.clone(), b"fallback".to_vec());
            drvs
        });
        let native = DrvClosure::new(root.clone(), {
            let mut drvs = BTreeMap::new();
            drvs.insert(root.clone(), b"native".to_vec());
            drvs
        });
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = FallbackWarningSubscriber {
            events: Arc::clone(&events),
        };
        let dispatch = tracing::Dispatch::new(subscriber);

        tracing::dispatcher::with_default(&dispatch, || {
            assert_eq!(
                compare_shadow_drv_closure(
                    &fallback,
                    &native,
                    "file instantiation",
                    Some(Path::new("/aos/default.nix")),
                    Some("pkgs.hello"),
                ),
                1
            );
        });

        let events = events.lock().expect("recorded shadow events lock");
        assert!(events.iter().any(|(level, _)| *level == Level::ERROR));
        let logged = events
            .iter()
            .map(|(_, event)| event.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            logged.contains("shadow native eval drv bytes diverged from nix-cli"),
            "{logged}"
        );
        assert!(logged.contains("operation=file instantiation"), "{logged}");
        assert!(logged.contains("/aos/default.nix"), "{logged}");
        assert!(logged.contains("pkgs.hello"), "{logged}");
        assert!(logged.contains("drv=/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root.drv"));
    }

    #[test]
    fn aos_nix_parallel_env_var_parses_worker_counts() {
        let mut config = NixEvalConfig::new();
        assert_eq!(config.native_parallel_workers(), None);

        config.set_aos_nix_parallel_env_var("4");
        assert_eq!(
            config.native_parallel_workers().map(|count| count.get()),
            Some(4)
        );

        // Falsy and invalid values disable parallel mode.
        for value in ["0", "off", "false", "no", "", "  ", "not-a-number"] {
            config.set_aos_nix_parallel_env_var("2");
            config.set_aos_nix_parallel_env_var(value);
            assert_eq!(
                config.native_parallel_workers(),
                None,
                "value {value:?} must disable parallel mode"
            );
        }
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn parallel_mode_options_disable_tier1_publishing() {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(NixEvalMode::Pure);
        config.set_native_jit(true);
        config.set_native_parallel_workers(std::num::NonZeroUsize::new(4));

        let options = tree_walk_options_from_config(&config).expect("options build");

        assert_eq!(
            options.parallel_workers().map(|count| count.get()),
            Some(4)
        );
        assert!(
            !options.jit_tier1_publish_enabled(),
            "AOS_NIX_JIT must be ignored under AOS_NIX_PARALLEL"
        );
    }
}

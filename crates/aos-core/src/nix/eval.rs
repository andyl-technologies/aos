//! The evaluation seam: turning Nix source into a `.drv` graph.
//!
//! [`NixEval`] abstracts only the *evaluation* phase of Nix: parsing `.nix`
//! files and reducing them to derivation files or JSON-rendered metadata. It
//! deliberately does not cover the build phase, which remains delegated to real
//! Nix through [`NixCli::realise`](crate::nix::NixCli::realise).
//!
//! The default implementation is [`NixCli`](crate::nix::NixCli), the permanent
//! C++ Nix oracle and fallback. The native implementation lives in the
//! `aos-nix` crate so `aos-core` stays lightweight.

use std::collections::BTreeMap;
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
use aos_nix::{
    NativeCliFallbackReason, NativeDrvClosure, NativeEvalError, NixNative,
    eval::{IfdRealizationError, IfdRealizer, TreeWalkOptions},
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

/// Native evaluator counters captured for the current process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeEvalStats {
    successes: NativeSuccessStats,
    fallbacks: NativeFallbackStats,
    shadow: NativeShadowStats,
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

/// Returns native evaluator counters captured for the current process.
pub fn native_eval_stats() -> NativeEvalStats {
    NativeEvalStats {
        successes: native_success_stats(),
        fallbacks: native_fallback_stats(),
        shadow: native_shadow_stats(),
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

    /// Returns a stable implementation name for diagnostics and tracing.
    fn name(&self) -> &'static str;
}

/// Evaluator settings that must be shared by native and C++ Nix evaluators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NixEvalConfig {
    current_system: Option<String>,
    store_dir: Option<String>,
    state_dir: Option<String>,
    log_dir: Option<String>,
    native_cache_root: Option<PathBuf>,
    trace_verbose: bool,
}

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

    /// Returns the configured Nix `system` value, if one was provided.
    pub fn current_system(&self) -> Option<&str> {
        self.current_system.as_deref()
    }

    /// Returns the configured Nix store directory, if one was provided.
    pub fn store_dir(&self) -> Option<&str> {
        self.store_dir.as_deref()
    }

    /// Returns the native evaluator cache root, if one was provided.
    ///
    /// The parse cache stores entries below this root's `parse/` child.
    pub fn native_cache_root(&self) -> Option<&Path> {
        self.native_cache_root.as_deref()
    }

    /// Returns whether `builtins.traceVerbose` should emit trace output.
    pub const fn trace_verbose(&self) -> bool {
        self.trace_verbose
    }

    /// Returns C++ Nix CLI options that reproduce these evaluator settings.
    pub(crate) fn cli_option_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(current_system) = self.current_system() {
            args.extend([
                "--option".to_string(),
                "system".to_string(),
                current_system.to_string(),
            ]);
        }
        if self.trace_verbose {
            args.extend([
                "--option".to_string(),
                "trace-verbose".to_string(),
                "true".to_string(),
            ]);
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
        vars
    }

    /// Applies C++ Nix environment bindings to a command.
    pub(crate) fn apply_cli_env(&self, command: &mut Command) {
        command.envs(self.cli_env_vars());
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
        self.store_dir = Some(validate_absolute_env_path(
            "NIX_STORE_DIR",
            store_dir.into(),
        )?);
        self.state_dir = Some(validate_absolute_env_path(
            "NIX_STATE_DIR",
            state_dir.into(),
        )?);
        self.log_dir = Some(validate_absolute_env_path("NIX_LOG_DIR", log_dir.into())?);
        Ok(())
    }

    /// Clears configured Nix store, state, and log directories.
    pub fn clear_store_dirs(&mut self) {
        self.store_dir = None;
        self.state_dir = None;
        self.log_dir = None;
    }

    /// Replaces the native evaluator cache root.
    ///
    /// The parse cache stores entries below this root's `parse/` child. Use
    /// [`Self::clear_native_cache_root`] for uncached native evaluation.
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

    /// Configures whether `builtins.traceVerbose` should emit trace output.
    pub fn set_trace_verbose(&mut self, trace_verbose: bool) {
        self.trace_verbose = trace_verbose;
    }

    fn from_env() -> Self {
        let mut config = Self {
            current_system: None,
            store_dir: None,
            state_dir: None,
            log_dir: None,
            native_cache_root: None,
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
        if let Ok(value) = std::env::var("AOS_NIX_CACHE") {
            config.set_aos_nix_cache_env_var(value);
        }

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

    fn set_cli_env_var(&mut self, name: &'static str, value: String) {
        match name {
            "NIX_STORE_DIR" => self.store_dir = Some(value),
            "NIX_STATE_DIR" => self.state_dir = Some(value),
            "NIX_LOG_DIR" => self.log_dir = Some(value),
            _ => {}
        }
    }
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
}

#[cfg(feature = "native-eval")]
impl NativeFallbackEval {
    fn new(verbose: u8, config: NixEvalConfig) -> Result<Self> {
        let native_options = tree_walk_options_from_config(&config)?;
        let fallback = NixCli::with_eval_config(verbose, config.clone());
        Ok(Self {
            native: native_with_ifd_realizer(
                NixNative::with_options(verbose, native_options)?,
                verbose,
                config,
            ),
            fallback,
        })
    }
}

#[cfg(feature = "native-eval")]
impl NixEval for NativeFallbackEval {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        match self.native.instantiate(file, attr) {
            Ok(path) => {
                observe_native_eval_success(NativeSuccessOperation::FileInstantiation);
                Ok(path)
            }
            Err(error) => {
                let Some(reason) = native_cli_fallback_reason(&error) else {
                    return Err(error);
                };
                warn_native_cli_fallback(&error, reason);
                self.fallback.instantiate(file, attr)
            }
        }
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        match self.native.instantiate_expr(expr) {
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
}

#[cfg(feature = "native-eval")]
impl NativeOnlyEval {
    fn new(verbose: u8, config: NixEvalConfig) -> Result<Self> {
        let native_options = tree_walk_options_from_config(&config)?;
        Ok(Self {
            native: native_with_ifd_realizer(
                NixNative::with_options(verbose, native_options)?,
                verbose,
                config,
            ),
        })
    }
}

#[cfg(feature = "native-eval")]
impl NixEval for NativeOnlyEval {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let path = self.native.instantiate(file, attr)?;
        observe_native_eval_success(NativeSuccessOperation::FileInstantiation);
        Ok(path)
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        let path = self.native.instantiate_expr(expr)?;
        observe_native_eval_success(NativeSuccessOperation::ExpressionInstantiation);
        Ok(path)
    }

    fn instantiate_closure(&self, file: &Path, attr: &str) -> Result<Option<DrvClosure>> {
        let closure = self.native.instantiate_closure(file, attr)?;
        observe_native_eval_success(NativeSuccessOperation::FileInstantiation);
        let (root, drvs) = closure.into_parts();
        Ok(Some(DrvClosure::new(root, drvs)))
    }

    fn eval_expr(&self, expr: &str) -> Result<String> {
        let value = self.native.eval_expr(expr)?;
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
}

#[cfg(feature = "native-eval")]
impl ShadowEval {
    fn new(verbose: u8, config: NixEvalConfig) -> Result<Self> {
        let native_options = tree_walk_options_from_config(&config)?;
        let fallback = NixCli::with_eval_config(verbose, config.clone());
        Ok(Self {
            native: native_with_ifd_realizer(
                NixNative::with_options(verbose, native_options)?,
                verbose,
                config,
            ),
            fallback,
        })
    }
}

#[cfg(feature = "native-eval")]
impl NixEval for ShadowEval {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let fallback = self.fallback.instantiate(file, attr)?;
        compare_shadow_file_drv_closure(&self.native, file, attr, &fallback);
        Ok(fallback)
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        let fallback = self.fallback.instantiate_expr(expr)?;
        compare_shadow_expr_drv_closure(&self.native, expr, &fallback);
        Ok(fallback)
    }

    fn instantiate_closure(&self, file: &Path, attr: &str) -> Result<Option<DrvClosure>> {
        let fallback = self.fallback.instantiate_closure(file, attr)?;
        compare_shadow_native_drv_closure(
            &fallback,
            self.native.instantiate_closure(file, attr),
            "file instantiation",
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
    );
}

#[cfg(feature = "native-eval")]
fn compare_shadow_expr_drv_closure(native: &NixNative, expr: &str, fallback: &Path) {
    compare_shadow_drv_closure_from_fallback_root(
        fallback,
        native.instantiate_expr_closure(expr),
        "expression instantiation",
    );
}

#[cfg(feature = "native-eval")]
fn compare_shadow_drv_closure_from_fallback_root(
    fallback_root: &Path,
    native: Result<NativeDrvClosure>,
    operation: &'static str,
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
                "shadow nix-cli drv closure could not be read"
            );
            return;
        }
    };

    compare_shadow_native_drv_closure(&fallback, native, operation);
}

#[cfg(feature = "native-eval")]
fn compare_shadow_native_drv_closure(
    fallback: &DrvClosure,
    native: Result<NativeDrvClosure>,
    operation: &'static str,
) {
    match native {
        Ok(native) => {
            let (root, drvs) = native.into_parts();
            let native = DrvClosure::new(root, drvs);
            let divergences = compare_shadow_drv_closure(fallback, &native);
            if divergences == 0 {
                observe_native_shadow_result(
                    NativeShadowOperation::DrvClosure,
                    NativeShadowOutcome::Match,
                );
                tracing::debug!(operation, "shadow native eval drv closure matched nix-cli");
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
                "shadow native eval drv closure did not complete"
            );
        }
    }
}

#[cfg(feature = "native-eval")]
fn compare_shadow_drv_closure(fallback: &DrvClosure, native: &DrvClosure) -> usize {
    let mut divergences = 0;
    if fallback.root() != native.root() {
        divergences += 1;
        tracing::error!(
            fallback = %fallback.root().display(),
            native = %native.root().display(),
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
                    "shadow native eval drv bytes diverged from nix-cli"
                );
            }
            None => {
                divergences += 1;
                tracing::error!(
                    drv = %path.display(),
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
                "shadow native eval produced extra drv outside nix-cli closure"
            );
        }
    }

    divergences
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

#[cfg(feature = "native-eval")]
fn tree_walk_options_from_config(config: &NixEvalConfig) -> Result<TreeWalkOptions> {
    let mut options = TreeWalkOptions::new();
    if let Some(store_dir) = config.store_dir() {
        options.set_store_dir(store_dir.as_bytes().to_vec())?;
    }
    if let Some(current_system) = config.current_system() {
        options.set_current_system(current_system.as_bytes().to_vec())?;
    }
    if let Some(cache_root) = config.native_cache_root() {
        options.set_parse_cache_root(cache_root.join("parse"));
    }
    options.set_trace_verbose(config.trace_verbose());
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn eval_config_renders_cpp_nix_env_vars() -> Result<()> {
        let config =
            NixEvalConfig::with_store_dirs("/aos/store", "/aos/var/nix", "/aos/var/nix/log/nix")?;

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

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_trace_verbose_to_native_options() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_trace_verbose(true);

        let options = tree_walk_options_from_config(&config)?;

        assert!(options.trace_verbose());
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_store_dir_to_native_options() -> Result<()> {
        let config =
            NixEvalConfig::with_store_dirs("/aos/store", "/aos/var/nix", "/aos/var/nix/log/nix")?;

        let options = tree_walk_options_from_config(&config)?;

        assert_eq!(options.store_dir(), b"/aos/store");
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_native_cache_root_to_parse_cache_options() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_native_cache_root("/aos/cache")?;

        let options = tree_walk_options_from_config(&config)?;

        assert_eq!(
            options.parse_cache_root(),
            Some(Path::new("/aos/cache/parse"))
        );
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
    fn native_diff_candidate_does_not_fall_back_to_cli() -> Result<()> {
        let candidate = select_native_diff_candidate_with_config(0, NixEvalConfig::new())?;

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
        let evaluator = NativeOnlyEval::new(0, NixEvalConfig::new())?;
        let before = native_success_stats();

        assert_eq!(evaluator.eval_expr("1 + 1")?, "2");

        let after = native_success_stats();
        assert!(after.expression_evaluations() > before.expression_evaluations());
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_fallback_eval_returns_native_instantiation_success() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = root.path().join("store");
        let state = root.path().join("state");
        let log = root.path().join("log");
        let config = NixEvalConfig::with_store_dirs(
            store.to_string_lossy().into_owned(),
            state.to_string_lossy().into_owned(),
            log.to_string_lossy().into_owned(),
        )?;
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
        };

        assert_eq!(stats.successes().total(), 6);
        assert_eq!(stats.fallbacks().total(), 9);
        assert_eq!(stats.shadow().total(), 51);
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
        assert_eq!(compare_shadow_drv_closure(&fallback, &matching), 0);

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

        assert_eq!(compare_shadow_drv_closure(&fallback, &native), 4);
    }
}

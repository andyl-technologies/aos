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
use crate::nix::NixCli;

#[cfg(feature = "native-eval")]
use aos_nix::{NativeCliFallbackReason, NativeEvalError, NixNative, eval::TreeWalkOptions};

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

        config
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

fn nix_env_from_process(name: &'static str) -> Option<(&'static str, String)> {
    std::env::var(name).ok().map(|value| (name, value))
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
        Ok(Self {
            native: NixNative::with_options(verbose, native_options)?,
            fallback: NixCli::with_eval_config(verbose, config),
        })
    }
}

#[cfg(feature = "native-eval")]
impl NixEval for NativeFallbackEval {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        match self.native.instantiate(file, attr) {
            Ok(path) => {
                let error: anyhow::Error = NativeEvalError::unsupported(format!(
                    "native instantiation materialization for {}",
                    path.display()
                ))
                .into();
                warn_native_cli_fallback(&error, NativeCliFallbackReason::Unsupported);
                self.fallback.instantiate(file, attr)
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
                let error: anyhow::Error = NativeEvalError::unsupported(format!(
                    "native expression instantiation materialization for {}",
                    path.display()
                ))
                .into();
                warn_native_cli_fallback(&error, NativeCliFallbackReason::Unsupported);
                self.fallback.instantiate_expr(expr)
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
            Ok(value) => Ok(value),
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
            native: NixNative::with_options(verbose, native_options)?,
        })
    }
}

#[cfg(feature = "native-eval")]
impl NixEval for NativeOnlyEval {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        self.native.instantiate(file, attr)
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        self.native.instantiate_expr(expr)
    }

    fn instantiate_closure(&self, file: &Path, attr: &str) -> Result<Option<DrvClosure>> {
        let closure = self.native.instantiate_closure(file, attr)?;
        let (root, drvs) = closure.into_parts();
        Ok(Some(DrvClosure::new(root, drvs)))
    }

    fn eval_expr(&self, expr: &str) -> Result<String> {
        self.native.eval_expr(expr)
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
        Ok(Self {
            native: NixNative::with_options(verbose, native_options)?,
            fallback: NixCli::with_eval_config(verbose, config),
        })
    }
}

#[cfg(feature = "native-eval")]
impl NixEval for ShadowEval {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let fallback = self.fallback.instantiate(file, attr)?;
        match self.native.instantiate(file, attr) {
            Ok(native) if native != fallback => {
                tracing::error!(
                    fallback = %fallback.display(),
                    native = %native.display(),
                    "shadow native eval diverged from nix-cli"
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(error = %error, "shadow native eval did not complete");
            }
        }
        Ok(fallback)
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        let fallback = self.fallback.instantiate_expr(expr)?;
        match self.native.instantiate_expr(expr) {
            Ok(native) if native != fallback => {
                tracing::error!(
                    fallback = %fallback.display(),
                    native = %native.display(),
                    "shadow native eval diverged from nix-cli"
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(error = %error, "shadow native eval did not complete");
            }
        }
        Ok(fallback)
    }

    fn eval_expr(&self, expr: &str) -> Result<String> {
        let fallback = self.fallback.eval_expr(expr)?;
        match self.native.eval_expr(expr) {
            Ok(native) if native != fallback => {
                tracing::error!("shadow native eval expression result diverged from nix-cli");
            }
            Ok(_) => {}
            Err(error) => {
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
fn native_cli_fallback_reason(error: &anyhow::Error) -> Option<NativeCliFallbackReason> {
    error
        .downcast_ref::<NativeEvalError>()
        .and_then(NativeEvalError::cli_fallback_reason)
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
fn record_native_cli_fallback(reason: NativeCliFallbackReason) -> u64 {
    let counter = match reason {
        NativeCliFallbackReason::Unsupported => &NATIVE_FALLBACK_UNSUPPORTED,
        NativeCliFallbackReason::Internal => &NATIVE_FALLBACK_INTERNAL,
    };
    counter.fetch_add(1, Ordering::Relaxed) + 1
}

#[cfg(feature = "native-eval")]
#[cfg(test)]
fn native_cli_fallback_count(reason: NativeCliFallbackReason) -> u64 {
    let counter = match reason {
        NativeCliFallbackReason::Unsupported => &NATIVE_FALLBACK_UNSUPPORTED,
        NativeCliFallbackReason::Internal => &NATIVE_FALLBACK_INTERNAL,
    };
    counter.load(Ordering::Relaxed)
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

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_fallback_recording_counts_by_reason() {
        let unsupported_before = native_cli_fallback_count(NativeCliFallbackReason::Unsupported);
        let internal_before = native_cli_fallback_count(NativeCliFallbackReason::Internal);

        let unsupported_after = record_native_cli_fallback(NativeCliFallbackReason::Unsupported);
        assert!(unsupported_after > unsupported_before);
        let unsupported_count = native_cli_fallback_count(NativeCliFallbackReason::Unsupported);
        assert!(unsupported_count >= unsupported_after);
        assert_eq!(
            native_cli_fallback_count(NativeCliFallbackReason::Internal),
            internal_before
        );

        let internal_after = record_native_cli_fallback(NativeCliFallbackReason::Internal);
        assert!(internal_after > internal_before);
        let internal_count = native_cli_fallback_count(NativeCliFallbackReason::Internal);
        assert!(internal_count >= internal_after);
    }
}

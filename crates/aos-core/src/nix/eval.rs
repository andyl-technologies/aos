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

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::Result;

use crate::nix::NixCli;

#[cfg(feature = "native-eval")]
use aos_nix::{NativeEvalError, NixNative, eval::TreeWalkOptions};

static NATIVE_MODE: OnceLock<NativeMode> = OnceLock::new();

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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NixEvalConfig {
    current_system: Option<String>,
    trace_verbose: bool,
}

impl NixEvalConfig {
    /// Creates evaluator settings using C++ Nix's ambient defaults.
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

    /// Returns the configured Nix `system` value, if one was provided.
    pub fn current_system(&self) -> Option<&str> {
        self.current_system.as_deref()
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

    /// Configures whether `builtins.traceVerbose` should emit trace output.
    pub fn set_trace_verbose(&mut self, trace_verbose: bool) {
        self.trace_verbose = trace_verbose;
    }
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
            Ok(path) => Ok(path),
            Err(error) if should_fallback(&error) => {
                tracing::warn!(error = %error, "native eval fell back to nix-cli");
                self.fallback.instantiate(file, attr)
            }
            Err(error) => Err(error),
        }
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        match self.native.instantiate_expr(expr) {
            Ok(path) => Ok(path),
            Err(error) if should_fallback(&error) => {
                tracing::warn!(error = %error, "native eval fell back to nix-cli");
                self.fallback.instantiate_expr(expr)
            }
            Err(error) => Err(error),
        }
    }

    fn eval_expr(&self, expr: &str) -> Result<String> {
        match self.native.eval_expr(expr) {
            Ok(value) => Ok(value),
            Err(error) if should_fallback(&error) => {
                tracing::warn!(error = %error, "native eval fell back to nix-cli");
                self.fallback.eval_expr(expr)
            }
            Err(error) => Err(error),
        }
    }

    fn name(&self) -> &'static str {
        "aos-nix"
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
fn should_fallback(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<NativeEvalError>()
        .is_some_and(NativeEvalError::permits_cli_fallback)
}

#[cfg(feature = "native-eval")]
fn tree_walk_options_from_config(config: &NixEvalConfig) -> Result<TreeWalkOptions> {
    let mut options = TreeWalkOptions::new();
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

    #[cfg(feature = "native-eval")]
    #[test]
    fn eval_config_maps_trace_verbose_to_native_options() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_trace_verbose(true);

        let options = tree_walk_options_from_config(&config)?;

        assert!(options.trace_verbose());
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
    fn native_fallback_decision_uses_native_error_taxonomy() {
        let unsupported: anyhow::Error = NativeEvalError::unsupported("missing primop").into();
        assert!(should_fallback(&unsupported));

        let internal: anyhow::Error = NativeEvalError::Internal {
            message: "bug".to_string(),
        }
        .into();
        assert!(should_fallback(&internal));

        let eval_error: anyhow::Error = NativeEvalError::EvalError {
            message: "type error".to_string(),
        }
        .into();
        assert!(!should_fallback(&eval_error));

        let other = anyhow::anyhow!("non-native error");
        assert!(!should_fallback(&other));
    }
}

//! Native RFC-0007 evaluator adapter for RFC-0011 configuration evaluation.
//!
//! [`NativeNixEvaluator`] implements the same [`NixEvaluator`](super::NixEvaluator)
//! boundary as the P1 stock evaluator. It reuses the exact `entry.nix`
//! renderer, evaluates that expression in-process under pure/restricted policy,
//! and returns canonical strict JSON. Unsupported native language features are
//! terminal in production; there is no implicit stock-Nix fallback.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aos_core::nix::native::{
    EvalMode, HeapMemoryBudget, NativeEvalError, NativeMissingOptionKind, NativeResourceLimit,
    NixNative, TreeWalkOptions,
};

use super::classify::{EvalClass, KillReason, MissingOption, MissingOptionKind};
use super::{EvalAttempt, NixEvaluator};

/// Persistent cache location for native on-host configuration evaluation.
pub const DEFAULT_NATIVE_CACHE_ROOT: &str = "/var/cache/aos/nix-eval";
/// Cache-placement override for hermetic checks and isolated recovery tools.
pub const NATIVE_CACHE_ROOT_ENV: &str = "AOS_NIX_EVAL_CACHE_ROOT";

/// Maximum nested Nix call depth accepted by the native evaluator.
pub const DEFAULT_MAX_CALL_DEPTH: usize = 4_096;
/// Deterministic IR-node budget for one production evaluation.
pub const DEFAULT_MAX_EVAL_STEPS: u64 = 50_000_000;
/// In-engine wall-clock deadline, below the enclosing systemd deadline.
pub const DEFAULT_MAX_EVAL_DURATION: std::time::Duration = std::time::Duration::from_secs(90);
/// Hard in-engine resident-memory ceiling, below the cgroup `MemoryMax`.
pub const DEFAULT_MAX_HEAP_BYTES: usize = 1536 * 1024 * 1024;

/// Native, eval-only implementation of the RFC-0011 evaluator seam.
pub struct NativeNixEvaluator {
    root: PathBuf,
    cache_root: PathBuf,
    verbose: u8,
    max_call_depth: usize,
    max_eval_steps: u64,
    max_eval_duration: std::time::Duration,
    max_heap_bytes: usize,
}

impl NativeNixEvaluator {
    /// Creates an evaluator using the durable production cache.
    pub fn new(root: impl Into<PathBuf>, verbose: u8) -> Self {
        Self {
            root: root.into(),
            cache_root: native_cache_root(|name| std::env::var_os(name)),
            verbose,
            max_call_depth: DEFAULT_MAX_CALL_DEPTH,
            max_eval_steps: DEFAULT_MAX_EVAL_STEPS,
            max_eval_duration: DEFAULT_MAX_EVAL_DURATION,
            max_heap_bytes: DEFAULT_MAX_HEAP_BYTES,
        }
    }

    /// Replaces the cache root, primarily for isolated tests.
    pub fn with_cache_root(mut self, cache_root: impl Into<PathBuf>) -> Self {
        self.cache_root = cache_root.into();
        self
    }

    /// Replaces the deterministic nested-call bound.
    pub fn with_max_call_depth(mut self, max_call_depth: usize) -> Self {
        self.max_call_depth = max_call_depth;
        self
    }

    /// Replaces the deterministic evaluated-node budget.
    pub fn with_max_eval_steps(mut self, max_eval_steps: u64) -> Self {
        self.max_eval_steps = max_eval_steps;
        self
    }

    /// Replaces the in-engine wall-clock deadline.
    pub fn with_max_eval_duration(mut self, max_eval_duration: std::time::Duration) -> Self {
        self.max_eval_duration = max_eval_duration;
        self
    }

    /// Replaces the hard resident heap-memory ceiling.
    pub fn with_max_heap_bytes(mut self, max_heap_bytes: usize) -> Self {
        self.max_heap_bytes = max_heap_bytes;
        self
    }

    fn options<'a>(
        &self,
        allowed_paths: impl IntoIterator<Item = &'a Path>,
    ) -> Result<TreeWalkOptions> {
        let parse_cache = self.cache_root.join("parse");
        let persist_cache = self.cache_root.join("persist");
        std::fs::create_dir_all(&parse_cache)
            .with_context(|| format!("creating native parse cache {}", parse_cache.display()))?;
        std::fs::create_dir_all(&persist_cache).with_context(|| {
            format!(
                "creating native persistent cache {}",
                persist_cache.display()
            )
        })?;

        let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Pure);
        options.set_max_call_depth(self.max_call_depth);
        options.set_max_eval_steps(Some(self.max_eval_steps));
        options.set_max_eval_duration(Some(self.max_eval_duration));
        options.set_heap_memory_budget(
            HeapMemoryBudget::new(self.max_heap_bytes)
                .context("configuring native evaluator heap budget")?,
        );
        options.set_enforce_heap_memory_budget(true);
        options.set_parse_cache_root(parse_cache);
        options.set_persist_cache_root(persist_cache);
        options.set_eval_cache_enabled(true);
        options.set_reject_ambient_search_path(true);
        options
            .set_path_literal_base(self.root.as_os_str().as_encoded_bytes().to_vec())
            .context("configuring native evaluator path base")?;

        options
            .add_allowed_path(self.root.as_os_str().as_encoded_bytes().to_vec())
            .context("allowing native eval root")?;
        for path in allowed_paths {
            options
                .add_allowed_path(path.as_os_str().as_encoded_bytes().to_vec())
                .with_context(|| format!("allowing native evaluator input {}", path.display()))?;
        }
        Ok(options)
    }

    /// Evaluates an expression to strict JSON with only the supplied paths
    /// added to the pure evaluator allowlist.
    ///
    /// # Errors
    ///
    /// Returns an error when cache setup, evaluator initialization, parsing,
    /// or evaluation fails.
    pub(super) fn eval_strict_json<'a>(
        &self,
        expression: &str,
        allowed_paths: impl IntoIterator<Item = &'a Path>,
    ) -> Result<String> {
        let options = self.options(allowed_paths)?;
        let evaluator = NixNative::with_options(self.verbose, options)
            .context("initializing native Nix evaluator")?;
        evaluator.eval_expr(expression)
    }
}

/// Resolves the cache location without granting any additional evaluator
/// authority. Production uses the fixed durable default; hermetic checks may
/// redirect only these disposable cache files to a writable directory.
fn native_cache_root(lookup: impl FnOnce(&str) -> Option<std::ffi::OsString>) -> PathBuf {
    lookup(NATIVE_CACHE_ROOT_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_NATIVE_CACHE_ROOT))
}

impl NixEvaluator for NativeNixEvaluator {
    fn evaluate(&self, attempt: &EvalAttempt<'_>) -> Result<EvalClass> {
        let renderer = super::stock::StockNixEvaluator::new(&self.root, self.verbose);
        let entry = renderer.write_native_entry(attempt)?;
        let expression = format!("import {}", super::stock::nix_path(&entry));
        let config_outputs = attempt
            .working_set
            .iter()
            .filter_map(|member| member.config_output.as_deref())
            .map(Path::new);
        let allowed_paths = std::iter::once(entry.as_path())
            .chain(std::iter::once(attempt.base_lib))
            .chain(std::iter::once(attempt.host_nix))
            .chain(attempt.facts_json)
            .chain(config_outputs);

        let options = self.options(allowed_paths)?;
        let evaluator = NixNative::with_options(self.verbose, options)
            .context("initializing native Nix evaluator")?;
        let module_owners = attempt.working_set.iter().filter_map(|member| {
            member
                .config_output
                .as_ref()
                .map(|output| (PathBuf::from(output), member.package.clone()))
        });
        let root_owners = attempt.working_set.iter().flat_map(|member| {
            std::iter::once((member.package.clone(), member.package.clone())).chain(
                member
                    .authorization
                    .owns
                    .iter()
                    .cloned()
                    .map(|root| (root, member.package.clone())),
            )
        });
        match evaluator.eval_expr_with_option_graph(&expression, module_owners, root_owners) {
            Ok(output) => {
                let json = output.json;
                let value: serde_json::Value = serde_json::from_str(&json)
                    .context("native evaluator returned invalid strict JSON")?;
                let object = value
                    .as_object()
                    .context("native evaluator manifest is not a JSON object")?;
                if object.is_empty() {
                    anyhow::bail!("native evaluator returned an empty manifest object");
                }
                Ok(EvalClass::NativeManifest {
                    manifest: serde_json::to_string(&value)
                        .context("canonicalizing native evaluator manifest")?,
                    option_graph: output.option_graph,
                })
            }
            Err(error) => classify_native_error(error),
        }
    }
}

fn classify_native_error(error: anyhow::Error) -> Result<EvalClass> {
    let Some(native) = error.downcast_ref::<NativeEvalError>() else {
        return Err(error.context("native Nix evaluation failed internally"));
    };
    match native {
        NativeEvalError::Unsupported { .. } | NativeEvalError::Internal { .. } => {
            Err(error.context("native Nix evaluator refused to fall back to stock Nix"))
        }
        NativeEvalError::ResourceLimit { resource, .. } => Ok(EvalClass::Killed(match resource {
            NativeResourceLimit::HeapMemory => KillReason::Oom,
            NativeResourceLimit::Steps
            | NativeResourceLimit::Time
            | NativeResourceLimit::CallDepth => KillReason::Timeout,
        })),
        NativeEvalError::MissingOptions { missing } => Ok(EvalClass::Missing(
            missing
                .iter()
                .map(|missing| MissingOption {
                    path: missing.path.clone(),
                    kind: match missing.kind {
                        NativeMissingOptionKind::UndeclaredWrite => {
                            MissingOptionKind::UndeclaredWrite
                        }
                        NativeMissingOptionKind::AbsentRootRead => {
                            MissingOptionKind::AbsentRootRead
                        }
                    },
                    read_by: missing.source_path.clone(),
                })
                .collect(),
        )),
        NativeEvalError::UndefinedOption { path, source_path } => Ok(EvalClass::UndefinedOption {
            path: path.clone(),
            file: source_path.clone(),
        }),
        NativeEvalError::Conflict { defs, .. } => Ok(EvalClass::Conflict {
            defs: defs
                .iter()
                .map(|definition| super::ConflictDef {
                    value: definition.value.clone(),
                    file: definition.source_path.clone(),
                })
                .collect(),
        }),
        NativeEvalError::Assertion {
            message,
            source_path,
        } => Ok(EvalClass::Assertion {
            msg: message.clone(),
            file: source_path.clone(),
        }),
        NativeEvalError::EvalError { message } => Ok(EvalClass::Other {
            stderr: message.clone(),
        }),
        NativeEvalError::StaticDivergence {
            binding,
            source_path,
        } => Ok(EvalClass::Other {
            stderr: format!(
                "static divergence in {source_path}: demanded recursive binding '{binding}'"
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_cache_root_defaults_and_accepts_placement_override() {
        assert_eq!(
            native_cache_root(|_| None),
            PathBuf::from(DEFAULT_NATIVE_CACHE_ROOT)
        );
        assert_eq!(
            native_cache_root(|name| {
                assert_eq!(name, NATIVE_CACHE_ROOT_ENV);
                Some(std::ffi::OsString::from("/tmp/aos-eval-cache"))
            }),
            PathBuf::from("/tmp/aos-eval-cache")
        );
        assert_eq!(
            native_cache_root(|_| Some(std::ffi::OsString::new())),
            PathBuf::from(DEFAULT_NATIVE_CACHE_ROOT)
        );
    }

    #[test]
    fn native_evaluator_returns_deterministic_strict_json() {
        let root = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let evaluator = NativeNixEvaluator::new(root.path(), 0).with_cache_root(cache.path());
        let json = evaluator
            .eval_strict_json("{ z = 2; a = 1; }", std::iter::empty())
            .unwrap();
        assert_eq!(json, r#"{"a":1,"z":2}"#);
    }

    #[test]
    fn native_evaluator_enforces_step_budget_in_engine() {
        let root = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let evaluator = NativeNixEvaluator::new(root.path(), 0)
            .with_cache_root(cache.path())
            .with_max_eval_steps(0);
        let error = evaluator
            .eval_strict_json("1", std::iter::empty())
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::ResourceLimit {
                resource: NativeResourceLimit::Steps,
                ..
            })
        ));
    }

    #[test]
    fn native_evaluator_enforces_wall_deadline_in_engine() {
        let root = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let evaluator = NativeNixEvaluator::new(root.path(), 0)
            .with_cache_root(cache.path())
            .with_max_eval_duration(std::time::Duration::ZERO);
        let error = evaluator
            .eval_strict_json("1", std::iter::empty())
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::ResourceLimit {
                resource: NativeResourceLimit::Time,
                ..
            })
        ));
    }

    #[test]
    fn native_evaluator_enforces_heap_budget_in_engine() {
        let root = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let evaluator = NativeNixEvaluator::new(root.path(), 0)
            .with_cache_root(cache.path())
            .with_max_heap_bytes(1);
        let error = evaluator
            .eval_strict_json("[ 1 2 3 ]", std::iter::empty())
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::ResourceLimit {
                resource: NativeResourceLimit::HeapMemory,
                ..
            })
        ));
    }

    #[test]
    fn unsupported_native_features_fail_closed() {
        let error = anyhow::Error::new(NativeEvalError::unsupported("test feature"));
        let rendered = format!("{:#}", classify_native_error(error).unwrap_err());
        assert!(rendered.contains("refused to fall back"), "{rendered}");
        assert!(rendered.contains("test feature"), "{rendered}");
    }

    #[test]
    fn call_depth_exhaustion_is_a_structured_timeout() {
        let error = anyhow::Error::new(NativeEvalError::ResourceLimit {
            resource: NativeResourceLimit::CallDepth,
            message: "maximum call depth exceeded".to_string(),
        });
        let class = classify_native_error(error).unwrap();
        assert_eq!(class, EvalClass::Killed(KillReason::Timeout));
    }

    #[test]
    fn native_missing_diagnostics_do_not_parse_human_messages() {
        let error = anyhow::Error::new(NativeEvalError::MissingOptions {
            missing: vec![aos_core::nix::native::NativeMissingOption {
                path: "firewall.port".to_string(),
                kind: NativeMissingOptionKind::UndeclaredWrite,
                source_path: Some("/config/module.nix".to_string()),
            }],
        });
        let class = classify_native_error(error).unwrap();
        let EvalClass::Missing(missing) = class else {
            panic!("expected missing-option classification");
        };
        assert_eq!(missing[0].path, "firewall.port");
        assert_eq!(missing[0].read_by.as_deref(), Some("/config/module.nix"));
    }

    #[test]
    fn unstructured_native_errors_remain_opaque() {
        let message = "The following option(s) are not declared: 'firewall.port'";
        let error = anyhow::Error::new(NativeEvalError::EvalError {
            message: message.to_string(),
        });
        assert_eq!(
            classify_native_error(error).unwrap(),
            EvalClass::Other {
                stderr: message.to_string()
            }
        );
    }

    #[test]
    fn static_divergence_preserves_structured_source_context() {
        let error = anyhow::Error::new(NativeEvalError::StaticDivergence {
            binding: "bottom".to_string(),
            source_path: "/config/module.nix".to_string(),
        });
        assert_eq!(
            classify_native_error(error).unwrap(),
            EvalClass::Other {
                stderr:
                    "static divergence in /config/module.nix: demanded recursive binding 'bottom'"
                        .to_string(),
            }
        );
    }

    #[test]
    fn native_structured_terminal_failures_preserve_classification() {
        let conflict = anyhow::Error::new(NativeEvalError::Conflict {
            path: "aos.security.firewall.forwardPolicy".to_string(),
            defs: vec![aos_core::nix::native::NativeConflictDef {
                value: Some("\"drop\"".to_string()),
                source_path: Some("/host.nix".to_string()),
            }],
        });
        assert!(matches!(
            classify_native_error(conflict).unwrap(),
            EvalClass::Conflict { defs } if defs.len() == 1
        ));

        let assertion = anyhow::Error::new(NativeEvalError::Assertion {
            message: "must be true".to_string(),
            source_path: None,
        });
        assert_eq!(
            classify_native_error(assertion).unwrap(),
            EvalClass::Assertion {
                msg: "must be true".to_string(),
                file: None,
            }
        );
    }
}

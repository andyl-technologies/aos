//! Evaluation-failure classification for the configuration operability surface.
//!
//! The module system already throws structured, sourced messages; the job here
//! is to map each terminal [`FixpointError`] to an operator-legible class and a
//! one-line summary, so `apm` and the journal can tag the failure class and
//! surface the last throw line (the one with `file:option`) without reformatting
//! the Nix trace into prose. Every class is a clean **no-op on the live system**
//! — these occur before any generation is created or `/etc` is touched.
//!
//! The classes mirror the operability.md table:
//!
//! ```text
//! Class            Operator-facing one-liner
//! ---------------  ---------------------------------------------------------
//! Assertion        config eval failed: assertion '<msg>' (<file>)
//! UndefinedOption  config eval failed: option '<path>' read but no provider …
//! Conflict         config eval failed: conflict on '<path>': '<a>' vs '<b>'
//! NoProvider       unresolved: '<path>' read by <reader> but no package provides it
//! AbiMismatch      config eval failed: '<path>' needs a module_abi the image lacks
//! Killed           config eval killed: exceeded MemoryMax / RuntimeMaxSec
//! NonConvergence   config eval did not converge (iteration trace)
//! EvalError        config eval failed: <opaque nix error>
//! ```
//!
//! Each class carries a distinct [`EvalFailureClass::exit_code`] so the calling
//! service can branch (the "distinct exit code" operability requirement) while
//! the human summary stays legible.

use super::{FixpointError, KillReason};

/// The operator-facing class of a terminal config-eval failure
/// (operability.md table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalFailureClass {
    /// A forced assertion fired (`lib/modules.nix:935`).
    Assertion,
    /// A declared option was read but left undefined with no provider
    /// (`lib/modules.nix:744`).
    UndefinedOption,
    /// A scalar/type conflict between definitions (`lib/modules.nix:721`).
    Conflict,
    /// No installed/registry package provides a read option (distinct exit).
    NoProvider,
    /// Every provider of an option excludes the running image `module_abi`.
    AbiMismatch,
    /// The eval subprocess was OOM-/timeout-killed by its transient scope.
    Killed,
    /// The fixpoint did not converge within the iteration cap.
    NonConvergence,
    /// A provider is present yet the option stays missing (read cycle).
    Unsatisfiable,
    /// Two installed packages own the same shared root (owned-root exclusivity).
    AmbiguousProvider,
    /// An owned root collides with a different installed package's name.
    ShadowedRoot,
    /// A `contributes` declaration is out of scope (no owner / not contributable).
    Contributable,
    /// Fetching a selected provider's config output failed terminally.
    Fetch,
    /// An opaque Nix failure that matched no known pattern.
    EvalError,
}

impl EvalFailureClass {
    /// A short stable tag for journald/structured output (`config-eval.class`).
    pub fn tag(self) -> &'static str {
        match self {
            EvalFailureClass::Assertion => "assertion",
            EvalFailureClass::UndefinedOption => "undefined-option",
            EvalFailureClass::Conflict => "conflict",
            EvalFailureClass::NoProvider => "no-provider",
            EvalFailureClass::AbiMismatch => "abi-mismatch",
            EvalFailureClass::Killed => "killed",
            EvalFailureClass::NonConvergence => "non-convergence",
            EvalFailureClass::Unsatisfiable => "unsatisfiable",
            EvalFailureClass::AmbiguousProvider => "ambiguous-provider",
            EvalFailureClass::ShadowedRoot => "shadowed-root",
            EvalFailureClass::Contributable => "contributable",
            EvalFailureClass::Fetch => "fetch-failed",
            EvalFailureClass::EvalError => "eval-error",
        }
    }

    /// A distinct process exit code per class (operability.md "distinct exit
    /// code"). Kept small and stable so a calling service can branch on it.
    pub fn exit_code(self) -> i32 {
        match self {
            EvalFailureClass::Assertion => 10,
            EvalFailureClass::UndefinedOption => 11,
            EvalFailureClass::Conflict => 12,
            EvalFailureClass::NoProvider => 13,
            EvalFailureClass::AbiMismatch => 14,
            EvalFailureClass::Killed => 15,
            EvalFailureClass::NonConvergence => 16,
            EvalFailureClass::Unsatisfiable => 17,
            EvalFailureClass::AmbiguousProvider => 18,
            EvalFailureClass::ShadowedRoot => 21,
            EvalFailureClass::Contributable => 22,
            EvalFailureClass::Fetch => 19,
            EvalFailureClass::EvalError => 20,
        }
    }
}

/// An operator-facing diagnostic for a terminal config-eval failure: its class,
/// a one-line summary, and the exit code the class maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalDiagnostic {
    /// The failure class (the journald tag and exit-code key).
    pub class: EvalFailureClass,
    /// The single-line operator summary (operability.md one-liner).
    pub summary: String,
}

impl EvalDiagnostic {
    /// The exit code for this diagnostic's class.
    pub fn exit_code(&self) -> i32 {
        self.class.exit_code()
    }
}

/// Map a terminal [`FixpointError`] to its operator [`EvalDiagnostic`]
/// (operability.md table).
///
/// The summary names the failure class and the last sourced throw line (the one
/// carrying `file`/`option`); the full Nix trace remains available at
/// `--verbose`. This is the single place the Rust boundary preserves the
/// module-system message, so the journal stays legible.
pub fn classify_failure(err: &FixpointError) -> EvalDiagnostic {
    let (class, summary) = match err {
        FixpointError::AssertionFailed { msg, file } => (
            EvalFailureClass::Assertion,
            match file {
                Some(file) => format!("config eval failed: assertion '{msg}' ({file})"),
                None => format!("config eval failed: assertion '{msg}'"),
            },
        ),
        FixpointError::UndefinedOption { path, file } => (
            EvalFailureClass::UndefinedOption,
            match file {
                Some(file) => format!(
                    "config eval failed: option '{path}' read but no provider (read by {file}; no module defines it)"
                ),
                None => format!(
                    "config eval failed: option '{path}' read but no provider (no module defines it)"
                ),
            },
        ),
        FixpointError::Conflict { defs } => {
            let rendered = defs
                .iter()
                .map(|d| {
                    let value = d.value.as_deref().unwrap_or("?");
                    match d.file.as_deref() {
                        Some(file) => format!("'{value}' ({file})"),
                        None => format!("'{value}'"),
                    }
                })
                .collect::<Vec<_>>()
                .join(" vs ");
            (
                EvalFailureClass::Conflict,
                format!("config eval failed: conflict between {rendered}"),
            )
        }
        FixpointError::NoProvider { path, read_by } => (
            EvalFailureClass::NoProvider,
            match read_by {
                Some(reader) => format!(
                    "unresolved: '{path}' read by {reader} but no installed/registry package provides it"
                ),
                None => {
                    format!("unresolved: '{path}' but no installed/registry package provides it")
                }
            },
        ),
        FixpointError::AbiMismatch { path, want } => (
            EvalFailureClass::AbiMismatch,
            format!(
                "config eval failed: every provider of '{path}' is incompatible with image module_abi {want}"
            ),
        ),
        FixpointError::SeedAbiMismatch(msg) => (
            EvalFailureClass::AbiMismatch,
            format!("config eval failed: {msg}"),
        ),
        FixpointError::EvalKilled { reason } => (
            EvalFailureClass::Killed,
            match reason {
                KillReason::Oom => "config eval killed: exceeded MemoryMax=2G (OOM)".to_string(),
                KillReason::Timeout => {
                    "config eval killed: exceeded RuntimeMaxSec=120s (timeout)".to_string()
                }
                KillReason::Unknown => "config eval killed by its transient scope".to_string(),
            },
        ),
        FixpointError::NonConvergence { iterations, .. } => (
            EvalFailureClass::NonConvergence,
            format!("config eval did not converge after {iterations} iterations (see trace)"),
        ),
        FixpointError::Unsatisfiable { path, provider } => (
            EvalFailureClass::Unsatisfiable,
            format!(
                "config eval failed: '{path}' is still missing after fetching '{provider}' (read cycle)"
            ),
        ),
        FixpointError::AmbiguousProvider {
            root,
            owner_a,
            owner_b,
        } => (
            EvalFailureClass::AmbiguousProvider,
            format!(
                "config eval failed: root '{root}' is owned by both '{owner_a}' and '{owner_b}' (owned roots are exclusive per system)"
            ),
        ),
        FixpointError::ShadowedRoot { root, owner } => (
            EvalFailureClass::ShadowedRoot,
            format!(
                "config eval failed: owned root '{root}' (owned by '{owner}') collides with a different installed package named '{root}'"
            ),
        ),
        FixpointError::Contributable {
            contributor,
            root,
            path,
            reason,
        } => (
            EvalFailureClass::Contributable,
            match reason {
                super::system_roots::ContributableError::NoOwner => format!(
                    "config eval failed: package '{contributor}' contributes to root '{root}' but no installed package owns it"
                ),
                super::system_roots::ContributableError::NotContributable => format!(
                    "config eval failed: package '{contributor}' contributes '{root}.{path}' but '{path}' is not in the owner's contributable set"
                ),
            },
        ),
        FixpointError::Fetch { provider, .. } => (
            EvalFailureClass::Fetch,
            format!("config eval failed: fetching config output for '{provider}' failed"),
        ),
        FixpointError::EvalError { stderr } => (
            EvalFailureClass::EvalError,
            format!("config eval failed: {}", last_error_line(stderr)),
        ),
    };
    EvalDiagnostic { class, summary }
}

/// The last `error:`-prefixed line of a Nix stderr (the innermost throw frame,
/// operability.md "surfaces the last throw line"), or the last non-empty line.
fn last_error_line(stderr: &str) -> String {
    stderr
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with("error:"))
        .or_else(|| stderr.lines().rev().find(|l| !l.trim().is_empty()))
        .unwrap_or("(no diagnostic)")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_eval::ConflictDef;

    #[test]
    fn assertion_one_liner_names_file() {
        let err = FixpointError::AssertionFailed {
            msg: "web needs firewall.forwardPolicy=accept but host.nix sets drop".to_string(),
            file: Some("web/config.nix:42".to_string()),
        };
        let d = classify_failure(&err);
        assert_eq!(d.class, EvalFailureClass::Assertion);
        assert_eq!(d.class.tag(), "assertion");
        assert!(d.summary.contains("assertion 'web needs firewall"));
        assert!(d.summary.contains("(web/config.nix:42)"));
    }

    #[test]
    fn undefined_option_names_reader() {
        let err = FixpointError::UndefinedOption {
            path: "firewall.forwardPolicy".to_string(),
            file: Some("web/config.nix".to_string()),
        };
        let d = classify_failure(&err);
        assert_eq!(d.class, EvalFailureClass::UndefinedOption);
        assert!(
            d.summary
                .contains("option 'firewall.forwardPolicy' read but no provider")
        );
        assert!(d.summary.contains("read by web/config.nix"));
    }

    #[test]
    fn conflict_lists_both_defs() {
        let err = FixpointError::Conflict {
            defs: vec![
                ConflictDef {
                    value: Some("accept".to_string()),
                    file: Some("web/config.nix".to_string()),
                },
                ConflictDef {
                    value: Some("drop".to_string()),
                    file: Some("host.nix".to_string()),
                },
            ],
        };
        let d = classify_failure(&err);
        assert_eq!(d.class, EvalFailureClass::Conflict);
        assert!(
            d.summary
                .contains("'accept' (web/config.nix) vs 'drop' (host.nix)")
        );
    }

    #[test]
    fn no_provider_is_distinct_exit() {
        let err = FixpointError::NoProvider {
            path: "firewall.forwardPolicy".to_string(),
            read_by: Some("web".to_string()),
        };
        let d = classify_failure(&err);
        assert_eq!(d.class, EvalFailureClass::NoProvider);
        assert!(
            d.summary
                .starts_with("unresolved: 'firewall.forwardPolicy' read by web")
        );
        // Distinct from every other class's exit code.
        assert_eq!(d.exit_code(), EvalFailureClass::NoProvider.exit_code());
        assert_ne!(d.exit_code(), EvalFailureClass::Conflict.exit_code());
    }

    #[test]
    fn oom_and_timeout_are_distinguished() {
        let oom = classify_failure(&FixpointError::EvalKilled {
            reason: KillReason::Oom,
        });
        assert_eq!(oom.class, EvalFailureClass::Killed);
        assert!(oom.summary.contains("MemoryMax=2G (OOM)"));

        let timeout = classify_failure(&FixpointError::EvalKilled {
            reason: KillReason::Timeout,
        });
        assert!(timeout.summary.contains("RuntimeMaxSec=120s (timeout)"));
    }

    #[test]
    fn opaque_eval_error_surfaces_last_throw() {
        let err = FixpointError::EvalError {
            stderr: "trace: foo\nerror: syntax error, unexpected '}'\n".to_string(),
        };
        let d = classify_failure(&err);
        assert_eq!(d.class, EvalFailureClass::EvalError);
        assert!(d.summary.contains("error: syntax error, unexpected '}'"));
    }

    #[test]
    fn every_class_has_a_unique_exit_code() {
        let classes = [
            EvalFailureClass::Assertion,
            EvalFailureClass::UndefinedOption,
            EvalFailureClass::Conflict,
            EvalFailureClass::NoProvider,
            EvalFailureClass::AbiMismatch,
            EvalFailureClass::Killed,
            EvalFailureClass::NonConvergence,
            EvalFailureClass::Unsatisfiable,
            EvalFailureClass::AmbiguousProvider,
            EvalFailureClass::ShadowedRoot,
            EvalFailureClass::Contributable,
            EvalFailureClass::Fetch,
            EvalFailureClass::EvalError,
        ];
        let mut codes: Vec<i32> = classes.iter().map(|c| c.exit_code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), classes.len(), "exit codes must be unique");
    }
}

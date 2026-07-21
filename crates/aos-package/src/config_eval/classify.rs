//! Stock-Nix eval-result classifier (RFC-0011 P1 fixpoint, build-spec §2).
//!
//! Stock Nix has no read-access instrumentation, so the resolver discovers the
//! provider set by *parsing* the human-readable throw strings stock Nix prints
//! to stderr. This module isolates that fragile parse behind one
//! [`classify`] function with an exhaustive test fixture, so the P2 aos-nix
//! evaluator (RFC-0007) can replace exactly this function with structured
//! errors and leave the driver's `match` arms untouched.
//!
//! The two *missing-option* cases are mechanically distinct and are detected
//! separately:
//!
//! ```text
//! Case A — undeclared WRITE  (lib/modules.nix:917 strict throw)
//!   error: The following option(s) are not declared:
//!     - 'firewall.zone' (defined in /nix/store/<h>-web-config/config.nix)
//!   ⇒ full leaf path; resolve by its root via SystemRoots.owner(root)
//!
//! Case B — absent-root READ  (raw stock-Nix attribute error, NOT :744)
//!   error: attribute 'firewall' missing
//!          at /nix/store/<h>-web-config/config.nix:42:14:
//!   ⇒ first path SEGMENT only; resolve via SystemRoots.owner(root)
//! ```
//!
//! Both cases now collapse to the same root-based dispatch (a [`SystemRoots`]
//! owner lookup, else a by-name structural fallback); the full Case-A path is
//! kept only for error text.
//!
//! [`SystemRoots`]: super::SystemRoots
//!
//! Conflating them produces an index miss and a false `NoProvider`, so the
//! [`MissingOptionKind`] on every [`MissingOption`] records which lookup shape
//! the driver must use.

use anyhow::{Context, Result};
use regex::Regex;

/// Why a runaway eval subprocess was killed (RFC-0011 build-spec §3).
///
/// Populated by the driver from the transient scope's exit cause
/// (`systemctl show --property=Result`), not guessed from stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillReason {
    /// The cgroup `MemoryMax` limit triggered an OOM kill.
    Oom,
    /// The `RuntimeMaxSec` deadline elapsed.
    Timeout,
    /// A kill was observed but its cause could not be attributed.
    Unknown,
}

impl std::fmt::Display for KillReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KillReason::Oom => "out-of-memory",
            KillReason::Timeout => "timeout",
            KillReason::Unknown => "killed",
        };
        f.write_str(s)
    }
}

/// Which lookup shape a [`MissingOption`] requires (build-spec §2 A-vs-B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingOptionKind {
    /// Case A: a write to an undeclared option. `path` is the full leaf path;
    /// the resolver dispatches on its root via `SystemRoots.owner(root)`, then a
    /// by-name structural fallback.
    UndeclaredWrite,
    /// Case B: a read of an absent root. `path` is only the first segment;
    /// resolved by that root via `SystemRoots.owner(root)`, then a by-name
    /// structural fallback.
    AbsentRootRead,
}

impl MissingOptionKind {
    /// Short label used in the non-convergence trace dump.
    pub fn label(self) -> &'static str {
        match self {
            MissingOptionKind::UndeclaredWrite => "write",
            MissingOptionKind::AbsentRootRead => "read",
        }
    }
}

/// One missing option signalled by a failed eval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingOption {
    /// The full leaf path (Case A) or the bare root segment (Case B).
    pub path: String,
    /// Which lookup shape the driver must use.
    pub kind: MissingOptionKind,
    /// The reader/writer locus: the defining `file` (Case A) or `file:line`
    /// (Case B), when stock Nix reported it.
    pub read_by: Option<String>,
}

/// One definition in a scalar/type conflict (build-spec §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictDef {
    /// The conflicting value as printed, when one was named.
    pub value: Option<String>,
    /// The defining file, when stock Nix reported it.
    pub file: Option<String>,
}

/// The classified outcome of a single stock-Nix eval attempt.
///
/// This is the seam between the string-parsing P1 evaluator and the driver: the
/// P2 aos-nix evaluator produces the same enum from structured engine errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalClass {
    /// Eval succeeded; carries the JSON manifest text from stdout.
    Manifest(String),
    /// One or more missing options (Case A: n≥1 writes; Case B: a single read).
    Missing(Vec<MissingOption>),
    /// A *declared* option left undefined with no default (`lib/modules.nix:744`).
    ///
    /// Terminal, **not** a fetch trigger: the declaring provider is already
    /// present, so fetching more packages cannot satisfy it.
    UndefinedOption {
        /// The declared-but-unset option path.
        path: String,
        /// The defining locus, when reported.
        file: Option<String>,
    },
    /// A scalar/type conflict between definitions.
    Conflict {
        /// Every conflicting definition stock Nix listed.
        defs: Vec<ConflictDef>,
    },
    /// A forced assertion failed.
    Assertion {
        /// The assertion message text as authored.
        msg: String,
        /// The defining locus, when reported.
        file: Option<String>,
    },
    /// The eval subprocess was OOM-/timeout-killed by its transient scope.
    Killed(KillReason),
    /// An opaque Nix failure that matched no known pattern.
    Other {
        /// The raw stderr, preserved verbatim for the operator.
        stderr: String,
    },
}

/// Classify a stock-Nix eval result into an [`EvalClass`].
///
/// `success` is the subprocess exit status; on success `stdout` is the JSON
/// manifest. On failure `stderr` is parsed against the build-spec §2 pattern
/// table, **matching the last throw block** (the innermost throw is the
/// terminal frame). An observed cgroup `kill` short-circuits to
/// [`EvalClass::Killed`] regardless of stderr.
///
/// Any `error:` that matches no known pattern becomes [`EvalClass::Other`] —
/// never a missing option, so the loop cannot fetch a wrong provider and mask
/// the real fault.
///
/// # Errors
///
/// Returns an error only if one of the internal pattern regexes fails to
/// compile, which is a programmer error in this module rather than a property
/// of the input.
pub fn classify(
    success: bool,
    stdout: &str,
    stderr: &str,
    kill: Option<KillReason>,
) -> Result<EvalClass> {
    if let Some(reason) = kill {
        return Ok(EvalClass::Killed(reason));
    }
    if success {
        return Ok(EvalClass::Manifest(stdout.to_string()));
    }

    // Most-specific terminal classes first, then the two missing-option cases.
    // Case A (undeclared write) carries its own distinct header, so it is
    // matched before the generic Case-B attribute error to avoid a stray
    // "attribute missing" shadowing a real strict throw.
    if let Some(defs) = parse_conflict(stderr)? {
        return Ok(EvalClass::Conflict { defs });
    }
    if let Some((msg, file)) = parse_assertion(stderr)? {
        return Ok(EvalClass::Assertion { msg, file });
    }
    if let Some(writes) = parse_undeclared_writes(stderr)? {
        return Ok(EvalClass::Missing(writes));
    }
    if let Some((path, file)) = parse_undefined_option(stderr)? {
        return Ok(EvalClass::UndefinedOption { path, file });
    }
    if let Some(read) = parse_absent_root(stderr)? {
        return Ok(EvalClass::Missing(vec![read]));
    }

    Ok(EvalClass::Other {
        stderr: stderr.to_string(),
    })
}

/// Compile a pattern, attributing a compile failure to this module.
fn re(pattern: &str) -> Result<Regex> {
    Regex::new(pattern).with_context(|| format!("compiling classify pattern: {pattern}"))
}

/// Case A — `^The following option(s) are not declared:` then the per-line
/// `- '<path>' (defined in <file>)` block. Anchored to the **last** header so
/// the innermost strict throw wins.
fn parse_undeclared_writes(stderr: &str) -> Result<Option<Vec<MissingOption>>> {
    let header = re(r"(?m)^\s*(?:error:\s*)?The following option\(s\) are not declared:")?;
    let item = re(r"^\s*-\s*'(?P<path>[^']+)'\s*\(defined in (?P<file>[^)]+)\)")?;

    let lines: Vec<&str> = stderr.lines().collect();
    // Index of the last header line.
    let Some(header_idx) = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| header.is_match(line))
        .map(|(idx, _)| idx)
        .next_back()
    else {
        return Ok(None);
    };

    let mut found = Vec::new();
    let mut started = false;
    for line in &lines[header_idx + 1..] {
        if let Some(caps) = item.captures(line) {
            started = true;
            found.push(MissingOption {
                path: caps["path"].to_string(),
                kind: MissingOptionKind::UndeclaredWrite,
                read_by: Some(caps["file"].to_string()),
            });
        } else if started && !line.trim().is_empty() {
            // The contiguous item block ended (e.g. the strict-mode epilogue).
            break;
        }
    }

    if found.is_empty() {
        Ok(None)
    } else {
        Ok(Some(found))
    }
}

/// Case B — raw `attribute '<root>' missing` plus the following
/// `at <file>:<line>`. Anchored to the **last** occurrence.
fn parse_absent_root(stderr: &str) -> Result<Option<MissingOption>> {
    let attr = re(r"attribute '(?P<root>[^']+)' missing")?;
    let at = re(r"^\s*at (?P<file>[^:]+):(?P<line>\d+)")?;

    let lines: Vec<&str> = stderr.lines().collect();
    let Some((idx, caps)) = lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| attr.captures(line).map(|caps| (idx, caps)))
        .next_back()
    else {
        return Ok(None);
    };

    let root = caps["root"].to_string();
    // The locus usually follows on the next non-empty line.
    let read_by = lines[idx + 1..]
        .iter()
        .take(3)
        .find_map(|line| at.captures(line))
        .map(|caps| format!("{}:{}", &caps["file"], &caps["line"]));

    Ok(Some(MissingOption {
        path: root,
        kind: MissingOptionKind::AbsentRootRead,
        read_by,
    }))
}

/// `:744` — `The option '<path>' is used but has no definition and no default
/// value.` Terminal; never a fetch trigger.
fn parse_undefined_option(stderr: &str) -> Result<Option<(String, Option<String>)>> {
    let opt = re(
        r"(?m)^\s*(?:error:\s*)?The option '(?P<path>[^']+)' is used but has no definition and no default value\.",
    )?;
    let at = re(r"^\s*at (?P<file>[^:]+):(?P<line>\d+)")?;

    let lines: Vec<&str> = stderr.lines().collect();
    let Some((idx, caps)) = lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| opt.captures(line).map(|caps| (idx, caps)))
        .next_back()
    else {
        return Ok(None);
    };

    let path = caps["path"].to_string();
    let file = lines[idx + 1..]
        .iter()
        .take(3)
        .find_map(|line| at.captures(line))
        .map(|caps| format!("{}:{}", &caps["file"], &caps["line"]));
    Ok(Some((path, file)))
}

/// Scalar/type conflict — `conflicting definition`/`conflicting value` marker,
/// then the listed `- '<value>' (defined in <file>)` definitions.
fn parse_conflict(stderr: &str) -> Result<Option<Vec<ConflictDef>>> {
    let marker = re(r"conflicting (?:definition|value)")?;
    if !marker.is_match(stderr) {
        return Ok(None);
    }
    let def = re(r"^\s*-\s*(?:'(?P<value>[^']*)'\s*)?\(defined in (?P<file>[^)]+)\)")?;
    let defs: Vec<ConflictDef> = stderr
        .lines()
        .filter_map(|line| def.captures(line))
        .map(|caps| ConflictDef {
            value: caps.name("value").map(|m| m.as_str().to_string()),
            file: caps.name("file").map(|m| m.as_str().to_string()),
        })
        .collect();
    Ok(Some(defs))
}

/// Forced assertion — `Failed assertions:` then the `- <msg>` lines.
fn parse_assertion(stderr: &str) -> Result<Option<(String, Option<String>)>> {
    let header = re(r"(?m)^\s*(?:error:\s*)?Failed assertions:")?;
    if !header.is_match(stderr) {
        return Ok(None);
    }
    let item = re(r"^\s*-\s*(?P<msg>.+)")?;
    let lines: Vec<&str> = stderr.lines().collect();
    let Some(header_idx) = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| header.is_match(line))
        .map(|(idx, _)| idx)
        .next_back()
    else {
        return Ok(None);
    };
    let msg = lines[header_idx + 1..]
        .iter()
        .find_map(|line| item.captures(line))
        .map(|caps| caps["msg"].trim().to_string())
        .unwrap_or_else(|| "assertion failed".to_string());
    Ok(Some((msg, None)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_yields_manifest() {
        let out = classify(true, "{\"ok\":true}", "", None).unwrap();
        assert_eq!(out, EvalClass::Manifest("{\"ok\":true}".to_string()));
    }

    #[test]
    fn kill_short_circuits_before_stderr_parse() {
        // Even with a parseable missing-option stderr, an observed kill wins.
        let stderr = "error: attribute 'firewall' missing";
        let out = classify(false, "", stderr, Some(KillReason::Oom)).unwrap();
        assert_eq!(out, EvalClass::Killed(KillReason::Oom));
    }

    #[test]
    fn case_a_undeclared_writes_multi() {
        let stderr = "\
error: The following option(s) are not declared:
  - 'firewall.forwardPolicy' (defined in /nix/store/h-web-config/config.nix)
  - 'firewall.zone' (defined in /nix/store/h-web-config/config.nix)

Because `_module.strict = true` on this evaluation, undeclared options are not allowed.";
        let out = classify(false, "", stderr, None).unwrap();
        let EvalClass::Missing(found) = out else {
            panic!("expected Missing, got {out:?}");
        };
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].path, "firewall.forwardPolicy");
        assert_eq!(found[0].kind, MissingOptionKind::UndeclaredWrite);
        assert_eq!(
            found[0].read_by.as_deref(),
            Some("/nix/store/h-web-config/config.nix")
        );
        assert_eq!(found[1].path, "firewall.zone");
    }

    #[test]
    fn case_b_absent_root_read() {
        let stderr = "\
error: attribute 'firewall' missing
       at /nix/store/h-web-config/config.nix:42:14:";
        let out = classify(false, "", stderr, None).unwrap();
        let EvalClass::Missing(found) = out else {
            panic!("expected Missing, got {out:?}");
        };
        assert_eq!(found.len(), 1);
        // Only the first segment, not a full path.
        assert_eq!(found[0].path, "firewall");
        assert_eq!(found[0].kind, MissingOptionKind::AbsentRootRead);
        assert_eq!(
            found[0].read_by.as_deref(),
            Some("/nix/store/h-web-config/config.nix:42")
        );
    }

    #[test]
    fn undefined_declared_option_is_terminal_not_missing() {
        let stderr = "\
error: The option 'firewall.zone' is used but has no definition and no default value.
       at /nix/store/h-firewall/config.nix:10:3:";
        let out = classify(false, "", stderr, None).unwrap();
        let EvalClass::UndefinedOption { path, file } = out else {
            panic!("expected UndefinedOption, got {out:?}");
        };
        assert_eq!(path, "firewall.zone");
        assert_eq!(file.as_deref(), Some("/nix/store/h-firewall/config.nix:10"));
    }

    #[test]
    fn conflict_lists_defs() {
        let stderr = "\
error: The option `services.x.port' has conflicting definition values:
  - '80' (defined in /nix/store/a/config.nix)
  - '443' (defined in /nix/store/b/config.nix)";
        let out = classify(false, "", stderr, None).unwrap();
        let EvalClass::Conflict { defs } = out else {
            panic!("expected Conflict, got {out:?}");
        };
        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0].value.as_deref(), Some("80"));
        assert_eq!(defs[1].file.as_deref(), Some("/nix/store/b/config.nix"));
    }

    #[test]
    fn assertion_message_captured() {
        let stderr = "\
error: Failed assertions:
  - firewall.zone must be set when forwardPolicy = accept";
        let out = classify(false, "", stderr, None).unwrap();
        let EvalClass::Assertion { msg, .. } = out else {
            panic!("expected Assertion, got {out:?}");
        };
        assert_eq!(msg, "firewall.zone must be set when forwardPolicy = accept");
    }

    #[test]
    fn unrecognized_error_is_opaque() {
        let stderr = "error: syntax error, unexpected '}'";
        let out = classify(false, "", stderr, None).unwrap();
        assert!(matches!(out, EvalClass::Other { .. }));
    }

    #[test]
    fn last_throw_block_wins_for_writes() {
        // An earlier benign-looking block is shadowed by the last header.
        let stderr = "\
error: The following option(s) are not declared:
  - 'aaa.x' (defined in /nix/store/old/config.nix)

trace: ...
error: The following option(s) are not declared:
  - 'firewall.zone' (defined in /nix/store/new/config.nix)";
        let out = classify(false, "", stderr, None).unwrap();
        let EvalClass::Missing(found) = out else {
            panic!("expected Missing");
        };
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "firewall.zone");
    }
}

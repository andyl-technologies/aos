//! Speculative parse-ahead producer for the parallel front-end (RFC-0007 S2/S6).
//!
//! A single dedicated thread — spawned only when a parallel demand pool exists
//! (`K >= 2`), never at `K == 1` — drains the shared
//! [`SpeculationFrontier`](super::parallel_demand::SpeculationFrontier) of
//! candidate files and parses each into the shared
//! [`SpeculativeParseStore`](super::parallel_demand::SpeculativeParseStore) ahead
//! of the demand that will force it. A demanding worker then adopts a stored IR
//! instead of parsing on the critical path.
//!
//! # Candidate sources
//!
//! - **Static path-literal edges** (S2): a file's literal `import ./x` /
//!   `callPackage ./x` targets, seeded from the root module and re-seeded from
//!   every file the producer parses.
//! - **`readDir` entries** (S6): the `.nix` entries of every directory the eval
//!   `readDir`s, fed by the evaluating threads *after* the directory's
//!   impure-input fingerprint is recorded. This is the load-bearing source on the
//!   AOS corpus, whose package graph is `readDir` + `callPackage (dir + name)`
//!   driven — computed edges that static speculation alone cannot see.
//!
//! Candidates enter the frontier as *raw, unresolved* paths; this producer does
//! the `canonicalize` + directory-to-`default.nix` + `.nix` filtering, keeping
//! that filesystem work off the evaluating threads.
//!
//! # Soundness
//!
//! Side-effect-free by construction: reads and parses candidate files only —
//! records no impure input, publishes no module, forces no value, raises no
//! error. **Only successful parses are stored; failures are dropped**, so the
//! demand path stays the sole source of import parse errors. Store keys are
//! `(realpath, content hash)`, so a file edited between speculation and demand is
//! a harmless miss. The `readDir` feed rides the listing the eval actually
//! obtained (after its fingerprint is recorded), so it observes nothing the eval
//! did not already observe.
//!
//! Design B (a dedicated thread, not worker-loop integration) is deliberately
//! simpler than "idle-only" integration into `DemandQueue::pop_or_park`; the
//! `K == 1`-never guard keeps it from racing the sole evaluating thread.
//!
//! # Budget (M-23)
//!
//! ```text
//! AOS_NIX_SPECULATE=parse          enable (anything but unset/off/0)
//! AOS_NIX_SPECULATE_MAX_FILES=8192 cap on files parsed per evaluation
//! ```

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::parallel_demand::{SharedEvalContext, SpeculationFrontier};
use super::*;

/// Speculation aggressiveness knobs (M-23), read from the environment.
pub(super) struct SpeculationBudget {
    /// Maximum files parsed per evaluation.
    max_files: usize,
}

impl SpeculationBudget {
    /// Reads the budget from `AOS_NIX_SPECULATE*`.
    ///
    /// Returns `None` (speculation disabled) when `AOS_NIX_SPECULATE` is unset,
    /// empty, `off`, or `0`.
    pub(super) fn from_env() -> Option<Self> {
        let mode = std::env::var("AOS_NIX_SPECULATE").ok()?;
        if matches!(mode.as_str(), "" | "off" | "0") {
            return None;
        }
        Some(Self {
            max_files: env_usize("AOS_NIX_SPECULATE_MAX_FILES", 8192),
        })
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// Seeds the frontier with a module's static path-literal edges.
///
/// Called at pool spawn with the root module. Candidates are raw `base`-relative
/// joins; resolution happens when the producer pops them.
pub(super) fn seed_static_edges(ir: &Ir, base: &[u8], shared: &Arc<SharedEvalContext>) {
    if let Some(frontier) = shared.speculation_frontier.as_ref() {
        push_static_edges(ir, base, frontier);
    }
}

/// Pushes a `readDir`ed directory's `.nix` entries onto the frontier (S6).
///
/// `dir` is the directory realpath and `entry_names` its raw entry names; only
/// `.nix`-suffixed names are enqueued, as raw `dir`-relative joins.
pub(super) fn seed_read_dir_entries(
    dir: &[u8],
    entry_names: &[Vec<u8>],
    shared: &Arc<SharedEvalContext>,
) {
    let Some(frontier) = shared.speculation_frontier.as_ref() else {
        return;
    };
    let dir_path = Path::new(OsStr::from_bytes(dir));
    for name in entry_names {
        if !name.ends_with(b".nix") {
            continue;
        }
        frontier.push(dir_path.join(OsStr::from_bytes(name.as_slice())));
    }
}

/// Drains the shared frontier, parsing each candidate into the store.
///
/// Runs until the frontier closes (pool teardown) or the file budget is hit.
/// Failures — unresolvable candidates, unreadable files, parse errors — are
/// dropped. Each parsed file's own static edges are fed back into the frontier.
pub(super) fn run_speculation_producer(shared: Arc<SharedEvalContext>, budget: SpeculationBudget) {
    let Some(frontier) = shared.speculation_frontier.as_ref() else {
        return;
    };
    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
    let mut parsed = 0usize;
    while let Some(candidate) = frontier.pop_or_park() {
        if parsed >= budget.max_files {
            break;
        }
        let Some(realpath) = resolve_candidate(&candidate) else {
            continue;
        };
        if !visited.insert(realpath.clone()) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&realpath) else {
            continue;
        };
        let Some(ir) = parse_isolated(&bytes) else {
            continue;
        };
        let base = realpath
            .parent()
            .map(|parent| parent.as_os_str().as_bytes().to_vec())
            .unwrap_or_default();
        push_static_edges(&ir, &base, frontier);
        parsed += 1;
        let key = ParseFileKey::for_source(realpath, &bytes);
        shared.speculation.insert(key, ir);
    }
}

/// Parses, resolves, lowers, and annotates isolated source, dropping any failure.
fn parse_isolated(bytes: &[u8]) -> Option<Ir> {
    let parsed = parse_bytes_with_symbols(bytes, SymbolTable::new()).ok()?;
    let resolved = resolve(parsed).ok()?;
    let mut ir = nix_lower(resolved).ok()?;
    let _ = annotate_import_ir(&mut ir);
    Some(ir)
}

/// Pushes a module's path-literal edges onto the frontier as raw `base`-relative
/// candidates. Home (`~`) and search-path (`<...>`) literals are skipped as
/// impure/config-dependent.
fn push_static_edges(ir: &Ir, base: &[u8], frontier: &SpeculationFrontier) {
    for node in ir.arena.nodes() {
        if node.kind != IrKind::Path {
            continue;
        }
        let IrData::Symbol(symbol) = node.data else {
            continue;
        };
        let Some(literal) = ir.symbols.resolve(symbol) else {
            continue;
        };
        if matches!(literal.first(), Some(b'~') | Some(b'<')) {
            continue;
        }
        let literal_path = Path::new(OsStr::from_bytes(literal));
        let candidate = if literal_path.is_absolute() {
            literal_path.to_path_buf()
        } else {
            Path::new(OsStr::from_bytes(base)).join(literal_path)
        };
        frontier.push(candidate);
    }
}

/// Resolves a raw candidate path to a canonical `.nix` module realpath, or
/// `None`.
///
/// Mirrors the demand path's resolution (canonicalize, directory to
/// `default.nix`) so the produced [`ParseFileKey`] matches the demand-side key.
/// Non-`.nix` targets (source files that merely appear as path literals) are
/// skipped to avoid wasted parses.
fn resolve_candidate(candidate: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(candidate).ok()?;
    let target = if canonical.is_dir() {
        canonical.join("default.nix")
    } else {
        canonical
    };
    let realpath = std::fs::canonicalize(&target).ok()?;
    if realpath.extension().and_then(|ext| ext.to_str()) != Some("nix") {
        return None;
    }
    Some(realpath)
}

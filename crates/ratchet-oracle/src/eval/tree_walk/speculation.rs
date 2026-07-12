//! Speculative parse-ahead producer for the parallel front-end (RFC-0007 S2/S3).
//!
//! A single dedicated thread — spawned only when a parallel demand pool exists
//! (`K >= 2`), never at `K == 1` — walks the import graph breadth-first along
//! *statically knowable* path-literal edges and parses the files it reaches into
//! the shared [`SpeculativeParseStore`](super::parallel_demand::SpeculativeParseStore)
//! ahead of the demand that will force them. A demanding worker then adopts a
//! stored IR instead of parsing on the critical path.
//!
//! This is the **design-B** producer (a dedicated thread, not worker-loop
//! integration): it is far simpler and touches none of the hot `DemandQueue`
//! parking path, at the cost of not being strictly "idle-only". The pool-only /
//! `K == 1`-never guard recovers most of C-19's intent (it never races the sole
//! evaluating thread). Worker-loop-integrated "idle-only" speculation (design A)
//! remains a possible future refinement if measurement ever justifies the
//! hot-path risk; its real seam is `DemandQueue::pop_or_park`, not the safe
//! precursor scheduler in `parallel.rs` (an anchor corrected during S2 recon).
//!
//! # Soundness
//!
//! Speculation is side-effect-free by construction: it reads candidate files and
//! parses/lowers them, but records no impure input, publishes no module, forces
//! no value, and raises no error. **Only successful parses are stored; failures
//! are dropped**, so the demand path stays the sole source of import parse errors
//! (the error-quarantine invariant). Store keys are `(realpath, content hash)`,
//! so a file edited between speculation and demand is a harmless miss.
//!
//! # Budget (M-23)
//!
//! Read from the environment, all disabled unless `AOS_NIX_SPECULATE` is set to a
//! non-`off` value:
//!
//! ```text
//! AOS_NIX_SPECULATE=parse         enable (anything but unset/off/0)
//! AOS_NIX_SPECULATE_DEPTH=2       BFS hops from the root file
//! AOS_NIX_SPECULATE_MAX_FILES=4096 cap on files parsed per evaluation
//! ```

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::parallel_demand::SharedEvalContext;
use super::*;

/// Speculation aggressiveness knobs (M-23), read from the environment.
pub(super) struct SpeculationBudget {
    /// Maximum BFS hops from the root file.
    depth: usize,
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
            depth: env_usize("AOS_NIX_SPECULATE_DEPTH", 2),
            max_files: env_usize("AOS_NIX_SPECULATE_MAX_FILES", 4096),
        })
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// Runs the breadth-first speculation producer until the frontier drains, the
/// budget is exhausted, or `shutdown` is set.
///
/// Each reached file is parsed into an isolated symbol table and, on success,
/// inserted into `shared.speculation`; parse failures are dropped. The frontier
/// is seeded from the root module's path-literal edges.
pub(super) fn run_speculation_producer(
    root_ir: Ir,
    root_base: Vec<u8>,
    shared: Arc<SharedEvalContext>,
    budget: SpeculationBudget,
    shutdown: Arc<AtomicBool>,
) {
    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
    let mut frontier: VecDeque<(PathBuf, usize)> = VecDeque::new();
    enqueue_edges(&root_ir, &root_base, 1, &budget, &mut visited, &mut frontier);

    let mut parsed = 0usize;
    while let Some((realpath, depth)) = frontier.pop_front() {
        if parsed >= budget.max_files || shutdown.load(Ordering::Relaxed) {
            return;
        }
        let Ok(bytes) = std::fs::read(&realpath) else {
            continue;
        };
        let Some(ir) = parse_isolated(&bytes) else {
            continue;
        };
        parsed += 1;
        // Enqueue this file's edges (resolved against its own directory) before
        // publishing, so the BFS keeps advancing while consumers drain the store.
        let base = realpath
            .parent()
            .map(|parent| parent.as_os_str().as_bytes().to_vec())
            .unwrap_or_default();
        enqueue_edges(&ir, &base, depth + 1, &budget, &mut visited, &mut frontier);
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

/// Enqueues the unvisited path-literal edges of `ir`, resolved against `base`.
///
/// `edge_depth` is the BFS depth assigned to the discovered candidates; nothing
/// is enqueued once it exceeds the budget depth.
fn enqueue_edges(
    ir: &Ir,
    base: &[u8],
    edge_depth: usize,
    budget: &SpeculationBudget,
    visited: &mut BTreeSet<PathBuf>,
    frontier: &mut VecDeque<(PathBuf, usize)>,
) {
    if edge_depth > budget.depth {
        return;
    }
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
        if let Some(candidate) = resolve_candidate(base, literal) {
            if visited.insert(candidate.clone()) {
                frontier.push_back((candidate, edge_depth));
            }
        }
    }
}

/// Resolves a path literal to a canonical `.nix` module realpath, or `None`.
///
/// Mirrors the demand path's resolution (relative-to-base join, directory to
/// `default.nix`, canonicalization) so the produced [`ParseFileKey`] matches the
/// demand-side key. Home (`~`) and search-path (`<...>`) literals are skipped as
/// impure/config-dependent, and non-`.nix` targets (source files that merely
/// appear as path literals) are skipped to avoid wasted parses.
fn resolve_candidate(base: &[u8], literal: &[u8]) -> Option<PathBuf> {
    if matches!(literal.first(), Some(b'~') | Some(b'<')) {
        return None;
    }
    let literal_path = Path::new(OsStr::from_bytes(literal));
    let joined = if literal_path.is_absolute() {
        literal_path.to_path_buf()
    } else {
        Path::new(OsStr::from_bytes(base)).join(literal_path)
    };
    let canonical = std::fs::canonicalize(&joined).ok()?;
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

//! Analysis orchestration and rendering.
//!
//! [`analyze`] joins the three layers: it takes a built
//! [`ClosureGraph`], scans the referrers of each suspect for the
//! suspect's hash, and folds the located sites into a [`Verdict`],
//! producing a [`ClosureAnalysis`] that serialises cleanly to JSON. The
//! `render_*` helpers print the same data as human-readable tables via
//! an `aos_core` [`Printer`].

use std::collections::HashMap;

use anyhow::Result;
use aos_core::output::Printer;
use serde::Serialize;

use crate::closure::{ClosureGraph, SuspectKind};
use crate::scan::{self, RefLocus, RefSite, store_hash, store_name};
use crate::verdict::{self, Verdict};

/// Deciding sites shown per referrer edge.
const SITES_PER_EDGE: usize = 3;

/// A row in the largest-paths breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct SizeRow {
    /// Store name (`gcc-14.3.0`).
    pub name: String,
    /// Full store path.
    pub path: String,
    /// The path's own NAR size in bytes.
    pub size: u64,
    /// Exclusive (dominator-subtree) size in bytes.
    pub exclusive: u64,
}

/// One referrer that pulls a suspect into the closure.
#[derive(Debug, Clone, Serialize)]
pub struct PullEdge {
    /// Name of the referring path.
    pub referrer: String,
    /// Full path of the referring path.
    pub referrer_path: String,
    /// The deciding reference sites within the referrer.
    pub sites: Vec<RefSite>,
}

/// A suspect together with its verdict and the edges that hold it in.
#[derive(Debug, Clone, Serialize)]
pub struct SuspectFinding {
    /// Store name.
    pub name: String,
    /// Full store path.
    pub path: String,
    /// Why the name was flagged.
    pub kind: SuspectKind,
    /// Exclusive closure bytes attributable to this suspect.
    pub exclusive: u64,
    /// The ruling derived from the located reference sites.
    pub verdict: Verdict,
    /// An optional clarifying note (e.g. a dead-RPATH explanation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The referrers that reference this suspect, with deciding sites.
    pub pulled_in_by: Vec<PullEdge>,
}

/// The full closure analysis for one target.
#[derive(Debug, Clone, Serialize)]
pub struct ClosureAnalysis {
    /// The profiled store path.
    pub target: String,
    /// Total NAR size of the closure in bytes.
    pub total_size: u64,
    /// Number of paths in the closure.
    pub path_count: usize,
    /// Largest paths by exclusive size.
    pub largest: Vec<SizeRow>,
    /// Suspect findings, largest exclusive size first.
    pub suspects: Vec<SuspectFinding>,
    /// Sum of exclusive sizes of leaking suspects (an upper bound; sizes
    /// overlap where suspects nest).
    pub removable_upper_bound: u64,
}

/// Analyses a closure: ranks paths by size and rules on every suspect.
///
/// Each suspect's referrers are scanned exactly once — a referrer that
/// pulls in several suspects is read a single time for all of their
/// hashes — keeping the cost close to one pass over the relevant subset
/// of the closure.
///
/// When `deep` is set, the structural suspect detector also runs (paths
/// shipping no shared library or executable), catching leaks of any name
/// at the cost of scanning much more of the closure.
///
/// # Errors
///
/// Returns an error only if a referrer directory cannot be traversed;
/// unreadable individual files are skipped within the scan.
pub fn analyze(graph: &ClosureGraph, top: usize, deep: bool) -> Result<ClosureAnalysis> {
    let largest = graph
        .by_exclusive()
        .into_iter()
        .take(top.max(1))
        .map(|i| SizeRow {
            name: store_name(&graph.paths[i]).to_string(),
            path: graph.paths[i].clone(),
            size: graph.sizes[i],
            exclusive: graph.exclusive[i],
        })
        .collect();

    let suspects = graph.suspects(deep);

    // Group the scan work by referrer so each is read only once: map a
    // referrer node to the set of suspect (hash -> path) it references.
    let mut work: HashMap<usize, HashMap<String, String>> = HashMap::new();
    for s in &suspects {
        let Some(hash) = store_hash(&s.path) else {
            continue;
        };
        for &r in &graph.rdeps[s.node] {
            work.entry(r)
                .or_default()
                .insert(hash.to_string(), s.path.clone());
        }
    }

    // Scan each referrer once; index results by suspect path.
    let mut sites_by_suspect: HashMap<String, Vec<(usize, Vec<RefSite>)>> = HashMap::new();
    for (referrer, targets) in &work {
        let found = scan::scan_path(&graph.paths[*referrer], targets)?;
        for (target_path, sites) in found {
            sites_by_suspect
                .entry(target_path)
                .or_default()
                .push((*referrer, sites));
        }
    }

    let mut findings = Vec::with_capacity(suspects.len());
    let mut removable: u64 = 0;
    for s in &suspects {
        let per_referrer = sites_by_suspect.remove(&s.path).unwrap_or_default();
        let all_sites: Vec<RefSite> = per_referrer
            .iter()
            .flat_map(|(_, sites)| sites.iter().cloned())
            .collect();
        let (v, note) = refine_verdict(&s.path, &all_sites);

        // Structural (no-`.so`/no-executable) suspects are only worth
        // surfacing when they are confirmed leaks: a large inert payload
        // ruled `runtime` is a legitimate data package (certificates,
        // time-zone data) and listing it would be noise. Named suspects
        // (build tools, interpreters) stay visible regardless, since
        // their mere presence is informative.
        if s.kind == SuspectKind::NoRuntimeArtifact && !v.is_leak() {
            continue;
        }
        if v.is_leak() {
            removable = removable.saturating_add(s.exclusive);
        }

        let pulled_in_by = per_referrer
            .into_iter()
            .map(|(r, sites)| {
                let deciding = verdict::deciding_sites(&sites, SITES_PER_EDGE)
                    .into_iter()
                    .cloned()
                    .collect();
                PullEdge {
                    referrer: store_name(&graph.paths[r]).to_string(),
                    referrer_path: graph.paths[r].clone(),
                    sites: deciding,
                }
            })
            .collect();

        findings.push(SuspectFinding {
            name: s.name.clone(),
            path: s.path.clone(),
            kind: s.kind,
            exclusive: s.exclusive,
            verdict: v,
            note,
            pulled_in_by,
        });
    }

    Ok(ClosureAnalysis {
        target: graph.paths[graph.root].clone(),
        total_size: graph.total_size(),
        path_count: graph.paths.len(),
        largest,
        suspects: findings,
        removable_upper_bound: removable,
    })
}

/// Rules on a reference, applying the dead-RPATH refinement.
///
/// The base verdict comes from [`verdict::verdict`]. It is then
/// downgraded to [`Verdict::Spurious`] when the *only* runtime-strength
/// evidence is an RPATH/RUNPATH entry and the target ships no shared
/// library: such an entry can never satisfy a load and is dead weight
/// (typically a build-time `-L`/rpath injected for a header-only or
/// tool-only dependency). Returns the verdict and an optional note.
pub fn refine_verdict(path: &str, sites: &[RefSite]) -> (Verdict, Option<String>) {
    let base = verdict::verdict(sites);
    if base != Verdict::Runtime {
        return (base, None);
    }
    let has_runpath = sites.iter().any(|s| s.locus == RefLocus::ElfRunpath);
    let has_other_runtime = sites.iter().any(|s| {
        matches!(
            s.locus,
            RefLocus::ElfInterp
                | RefLocus::ElfLoadable
                | RefLocus::Shebang
                | RefLocus::ScriptBody
                | RefLocus::SymlinkTarget
                | RefLocus::PlainData
        )
    });
    if has_runpath && !has_other_runtime && !scan::provides_shared_lib(path) {
        return (
            Verdict::Spurious,
            Some(
                "dead RPATH/RUNPATH: target ships no shared library; drop the build-time -L/rpath"
                    .to_string(),
            ),
        );
    }
    (base, None)
}

/// Renders a [`ClosureAnalysis`] as human-readable tables.
pub fn render(printer: &Printer, a: &ClosureAnalysis) {
    printer.header(&format!("Closure profile: {}", store_name(&a.target)));
    printer.kv("Store path", &a.target);
    printer.kv("Paths", &a.path_count.to_string());
    printer.kv("Total size", &human(a.total_size));
    printer.plain("");

    if !a.largest.is_empty() {
        printer.header(&format!(
            "Largest paths (top {}, by exclusive size):",
            a.largest.len()
        ));
        for row in &a.largest {
            printer.plain(&format!(
                "  {:>10}  {:>10}  {}",
                human(row.exclusive),
                human(row.size),
                row.name,
            ));
        }
        printer.plain("    (col 1 = exclusive/dominated subtree, col 2 = own size)");
        printer.plain("");
    }

    let leaks: Vec<&SuspectFinding> = a.suspects.iter().filter(|s| s.verdict.is_leak()).collect();
    let kept: usize = a.suspects.len() - leaks.len();

    printer.header(&format!(
        "Suspect build/dev artifacts: {} flagged, {} confirmed leaks, {} load-bearing",
        a.suspects.len(),
        leaks.len(),
        kept,
    ));
    if a.suspects.is_empty() {
        printer.plain("  none — closure is clean of known build tooling");
    }

    for s in &a.suspects {
        printer.plain(&format!(
            "  [{:^8}] {:<28} {:>10} exclusive  ({})",
            s.verdict.label(),
            s.name,
            human(s.exclusive),
            s.kind.label(),
        ));
        for edge in s.pulled_in_by.iter().take(4) {
            for site in &edge.sites {
                printer.plain(&format!(
                    "      via {} -> {} ({})",
                    edge.referrer,
                    site.locus.label(),
                    site.file,
                ));
            }
        }
        if s.pulled_in_by.is_empty() {
            printer.plain("      (reference recorded but not located in content)");
        }
        if let Some(note) = &s.note {
            printer.plain(&format!("      note: {note}"));
        }
        if s.verdict.is_leak() {
            printer.plain(&format!("      fix: {}", s.verdict.recommendation()));
        }
    }
    printer.plain("");
    printer.header(&format!(
        "Removable upper bound: {} across {} leak(s)",
        human(a.removable_upper_bound),
        leaks.len(),
    ));
    printer.plain("    (exclusive sizes overlap where suspects nest; treat as a ceiling)");
}

/// Renders a single `pkg -> dep` reference justification.
pub fn render_refs(
    printer: &Printer,
    pkg: &str,
    dep: &str,
    sites: &[RefSite],
    v: Verdict,
    note: Option<&str>,
) {
    printer.header(&format!(
        "Why {} references {}",
        store_name(pkg),
        store_name(dep)
    ));
    printer.kv("Referrer", pkg);
    printer.kv("Dependency", dep);
    printer.kv("Verdict", v.label());
    if let Some(note) = note {
        printer.kv("Note", note);
    }
    printer.plain("");
    if sites.is_empty() {
        printer.plain("  No occurrence of the dependency hash was found in the referrer's");
        printer.plain("  content. The reference is metadata-only (stale or registration-only).");
        return;
    }
    printer.header(&format!("Reference sites ({}):", sites.len()));
    for site in sites {
        printer.plain(&format!("  {:<28} {}", site.locus.label(), site.file));
    }
    if v.is_leak() {
        printer.plain("");
        printer.plain(&format!("fix: {}", v.recommendation()));
    }
}

/// Formats a byte count as a human-readable size with binary units.
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_sizes() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(1024), "1.0 KiB");
        assert_eq!(human(1024 * 1024), "1.0 MiB");
        assert_eq!(human(1536 * 1024 * 1024), "1.5 GiB");
    }
}

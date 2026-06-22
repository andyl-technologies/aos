//! Runtime-closure graph with dominator-tree size attribution.
//!
//! [`ClosureGraph`] enumerates a store path's runtime closure, records
//! each path's NAR size and intra-closure references, and computes — via
//! the Lengauer-style Cooper-Harvey-Kennedy dominator algorithm — each
//! path's **exclusive size**: the total bytes that would leave the
//! closure if that path could be dropped. Exclusive size is what turns a
//! flat dependency list into a priority list: a leaked build tool that
//! also drags in a 200 MB toolchain subtree matters far more than one
//! that stands alone.
//!
//! The graph also flags **suspects** — paths whose names mark them as
//! build-time tooling or dev outputs (`gcc`, `meson`, `*-dev`, …) that
//! have no business in a production image. A suspect is only a lead; the
//! [`scan`](crate::scan) + [`verdict`](crate::verdict) layers confirm
//! whether each one is genuinely load-bearing.

use std::collections::HashMap;

use anyhow::{Context, Result};
use aos_core::nix::NixCli;
use serde::Serialize;

use crate::scan::{self, store_name};

/// Sentinel for "no immediate dominator computed yet".
const UNDEFINED: usize = usize::MAX;

/// Minimum exclusive size for the structural (no-`.so`/no-executable)
/// suspect detector to fire. Below this, the closure is dominated by
/// tiny `/etc` fragments and unit files — legitimate inert config whose
/// flagging would be pure noise — so structural detection is reserved
/// for substantial inert payloads (header trees, stray sources).
const STRUCTURAL_MIN_SIZE: u64 = 512 * 1024;

/// A realised runtime closure as an analysable graph.
pub struct ClosureGraph {
    /// Index of the root (the profiled target) in [`paths`](Self::paths).
    pub root: usize,
    /// Store paths, one per node; the canonical node ordering.
    pub paths: Vec<String>,
    /// NAR size in bytes per node, parallel to [`paths`](Self::paths).
    pub sizes: Vec<u64>,
    /// Forward edges: `refs[i]` are the nodes that node `i` references
    /// (restricted to the closure; self-references removed).
    pub refs: Vec<Vec<usize>>,
    /// Reverse edges: `rdeps[i]` are the nodes that reference node `i`.
    pub rdeps: Vec<Vec<usize>>,
    /// Exclusive (dominator-subtree) size per node.
    pub exclusive: Vec<u64>,
    /// Lookup from store path to node index.
    index: HashMap<String, usize>,
}

impl ClosureGraph {
    /// Builds the closure graph for a realised store `root`.
    ///
    /// Enumerates the closure with `nix-store --query --requisites`, then
    /// gathers per-path references and NAR sizes and computes exclusive
    /// sizes.
    ///
    /// # Errors
    ///
    /// Returns an error if the closure query or any path-info query
    /// fails (for example, if `root` is not a valid store path).
    pub fn build(nix: &NixCli, root: &str) -> Result<Self> {
        let paths = nix
            .closure(root)
            .with_context(|| format!("enumerating closure of {root}"))?;
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let infos = nix
            .path_info_batch(&refs)
            .context("gathering path metadata")?;

        let index: HashMap<String, usize> = paths
            .iter()
            .enumerate()
            .map(|(i, p)| (p.clone(), i))
            .collect();

        let root_idx = *index
            .get(root)
            .with_context(|| format!("root {root} missing from its own closure"))?;

        let n = paths.len();
        let mut sizes = vec![0u64; n];
        let mut fwd = vec![Vec::new(); n];
        let mut rev = vec![Vec::new(); n];

        // `path_info_batch` preserves input order, so info[i] matches paths[i].
        for (i, info) in infos.iter().enumerate() {
            sizes[i] = info.nar_size;
            for r in &info.references {
                if let Some(&j) = index.get(r)
                    && j != i
                {
                    fwd[i].push(j);
                    rev[j].push(i);
                }
            }
        }

        let exclusive = exclusive_sizes(n, root_idx, &fwd, &rev, &sizes);

        Ok(Self {
            root: root_idx,
            paths,
            sizes,
            refs: fwd,
            rdeps: rev,
            exclusive,
            index,
        })
    }

    /// Total NAR size of the whole closure in bytes.
    pub fn total_size(&self) -> u64 {
        self.sizes.iter().sum()
    }

    /// Returns the node index for a store path, if present in the closure.
    pub fn node(&self, path: &str) -> Option<usize> {
        self.index.get(path).copied()
    }

    /// Returns node indices sorted by exclusive size, largest first.
    pub fn by_exclusive(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.paths.len()).collect();
        order.sort_by(|&a, &b| self.exclusive[b].cmp(&self.exclusive[a]));
        order
    }

    /// Identifies suspect paths — build tooling, dev outputs, and paths
    /// that ship no runnable artifact — that should not appear in a
    /// runtime closure, sorted by exclusive size.
    ///
    /// Two detectors run per path:
    ///
    /// 1. **Name-based** ([`classify_suspect`]) — recognises known build
    ///    tools, interpreters, and `*-dev`/`*-doc` split outputs.
    /// 2. **Structural** — a path that ships neither a shared library nor
    ///    an executable cannot be loaded or run, so its presence in a
    ///    runtime closure is inherently questionable. This catches leaks
    ///    of any name (a header-only package dragged in by a dead RPATH,
    ///    a stray source tree). Genuine data packages (certificates,
    ///    time-zone data, fonts) also match but are kept by the verdict
    ///    layer, which sees their real data references.
    ///
    /// The structural detector (point 2) walks each candidate's files and
    /// scans its referrers, which is costly on a large closure, so it runs
    /// only when `deep` is set; the name-based detector always runs.
    ///
    /// The root itself is never reported as a suspect.
    pub fn suspects(&self, deep: bool) -> Vec<Suspect> {
        let mut found: Vec<Suspect> = self
            .paths
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != self.root)
            .filter_map(|(i, path)| {
                let name = store_name(path);
                let kind = classify_suspect(name).or_else(|| {
                    if deep
                        && self.exclusive[i] >= STRUCTURAL_MIN_SIZE
                        && !scan::provides_shared_lib(path)
                        && !scan::provides_executable(path)
                    {
                        Some(SuspectKind::NoRuntimeArtifact)
                    } else {
                        None
                    }
                })?;
                Some(Suspect {
                    node: i,
                    path: path.clone(),
                    name: name.to_string(),
                    kind,
                    exclusive: self.exclusive[i],
                })
            })
            .collect();
        found.sort_by(|a, b| b.exclusive.cmp(&a.exclusive));
        found
    }
}

/// A closure path flagged as build-time tooling or a dev output.
#[derive(Debug, Clone, Serialize)]
pub struct Suspect {
    /// Node index within the owning [`ClosureGraph`].
    #[serde(skip)]
    pub node: usize,
    /// Full store path.
    pub path: String,
    /// Human name component (`gcc-14.3.0`).
    pub name: String,
    /// Why the name is suspicious.
    pub kind: SuspectKind,
    /// Bytes freed from the closure if this path (and its exclusively
    /// dominated subtree) were removed.
    pub exclusive: u64,
}

/// The reason a path's name marks it as a suspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuspectKind {
    /// A compiler/linker toolchain component.
    Toolchain,
    /// A build system or build-time code generator.
    BuildSystem,
    /// A language runtime that is frequently build-only.
    Interpreter,
    /// A split dev/doc output (`*-dev`, `*-doc`, …).
    DevOutput,
    /// Ships neither a shared library nor an executable: nothing in it
    /// can be loaded or run at runtime (structural detection).
    NoRuntimeArtifact,
}

impl SuspectKind {
    /// Returns a short human label.
    pub fn label(self) -> &'static str {
        match self {
            SuspectKind::Toolchain => "toolchain",
            SuspectKind::BuildSystem => "build-system",
            SuspectKind::Interpreter => "interpreter",
            SuspectKind::DevOutput => "dev-output",
            SuspectKind::NoRuntimeArtifact => "no .so/exe",
        }
    }
}

/// Classifies a store name as a suspect, or `None` if it looks like a
/// legitimate runtime component.
fn classify_suspect(name: &str) -> Option<SuspectKind> {
    // Dev/doc/debug split outputs by suffix.
    for suffix in ["-dev", "-doc", "-man", "-info", "-debug", "-devdoc"] {
        if name.ends_with(suffix) {
            return Some(SuspectKind::DevOutput);
        }
    }
    // Build tooling by leading package name (before the version dash).
    let pname = pname_of(name);
    const TOOLCHAIN: &[&str] = &[
        "gcc",
        "binutils",
        "bootstrap-tools",
        "clang",
        "llvm",
        "lld",
        "mrustc",
        "linux-headers",
        "glibc-headers",
        "musl-headers",
    ];
    const BUILD_SYSTEM: &[&str] = &[
        "meson",
        "ninja",
        "cmake",
        "autoconf",
        "automake",
        "libtool",
        "make",
        "gnumake",
        "bazel",
        "m4",
        "gperf",
        "bison",
        "flex",
        "pkg-config",
        "pkgconf",
        "patchelf",
        "gettext",
        "texinfo",
        "help2man",
        "doxygen",
    ];
    const INTERPRETER: &[&str] = &["perl", "python3", "python2", "python", "ruby"];

    if TOOLCHAIN.contains(&pname) {
        Some(SuspectKind::Toolchain)
    } else if BUILD_SYSTEM.contains(&pname) {
        Some(SuspectKind::BuildSystem)
    } else if INTERPRETER.contains(&pname) {
        Some(SuspectKind::Interpreter)
    } else {
        None
    }
}

/// Extracts the package-name component from a store name by stripping the
/// first `-<digit>...` version segment (`gcc-14.3.0` -> `gcc`).
fn pname_of(name: &str) -> &str {
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            return &name[..i];
        }
        i += 1;
    }
    name
}

/// Computes exclusive (dominator-subtree) sizes for every node.
///
/// Builds the dominator tree of the forward graph rooted at `root`, then
/// sums NAR sizes up the tree so each node's value covers itself plus
/// everything it uniquely dominates.
fn exclusive_sizes(
    n: usize,
    root: usize,
    fwd: &[Vec<usize>],
    rev: &[Vec<usize>],
    sizes: &[u64],
) -> Vec<u64> {
    let (order, post) = postorder(n, root, fwd);
    let idom = compute_idoms(root, fwd, rev, &order, &post);

    // Process nodes children-before-parents (ascending postorder number),
    // accumulating subtree sizes into immediate dominators.
    let mut excl = sizes.to_vec();
    let mut by_post: Vec<usize> = order.clone();
    by_post.sort_by_key(|&node| post[node]);
    for &node in &by_post {
        if node == root || idom[node] == UNDEFINED {
            continue;
        }
        let parent = idom[node];
        excl[parent] = excl[parent].saturating_add(excl[node]);
    }
    excl
}

/// Returns `(reachable_nodes_in_postorder, postorder_number_per_node)`.
///
/// Unreachable nodes get postorder number `0` and are absent from the
/// returned order; reachable nodes get distinct ascending numbers with
/// the root highest.
fn postorder(n: usize, root: usize, fwd: &[Vec<usize>]) -> (Vec<usize>, Vec<usize>) {
    let mut visited = vec![false; n];
    let mut post = vec![0usize; n];
    let mut order = Vec::new();
    // Iterative DFS: stack of (node, next-child-cursor).
    let mut stack: Vec<(usize, usize)> = Vec::new();
    visited[root] = true;
    stack.push((root, 0));
    while let Some(&mut (node, ref mut cursor)) = stack.last_mut() {
        if *cursor < fwd[node].len() {
            let child = fwd[node][*cursor];
            *cursor += 1;
            if !visited[child] {
                visited[child] = true;
                stack.push((child, 0));
            }
        } else {
            post[node] = order.len();
            order.push(node);
            stack.pop();
        }
    }
    (order, post)
}

/// Computes immediate dominators via Cooper-Harvey-Kennedy iteration.
fn compute_idoms(
    root: usize,
    _fwd: &[Vec<usize>],
    rev: &[Vec<usize>],
    postorder: &[usize],
    post: &[usize],
) -> Vec<usize> {
    let n = post.len();
    let mut idom = vec![UNDEFINED; n];
    idom[root] = root;

    // Reverse postorder: root first, then descending postorder number.
    let mut rpo: Vec<usize> = postorder.to_vec();
    rpo.reverse();

    let reachable: Vec<bool> = {
        let mut r = vec![false; n];
        for &node in postorder {
            r[node] = true;
        }
        r
    };

    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == root {
                continue;
            }
            let mut new_idom = UNDEFINED;
            for &p in &rev[b] {
                if !reachable[p] || idom[p] == UNDEFINED {
                    continue;
                }
                new_idom = if new_idom == UNDEFINED {
                    p
                } else {
                    intersect(p, new_idom, &idom, post)
                };
            }
            if new_idom != UNDEFINED && idom[b] != new_idom {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
    idom
}

/// Walks two finger pointers up the partial dominator tree until they
/// meet, per Cooper-Harvey-Kennedy `intersect`.
fn intersect(mut a: usize, mut b: usize, idom: &[usize], post: &[usize]) -> usize {
    while a != b {
        while post[a] < post[b] {
            a = idom[a];
        }
        while post[b] < post[a] {
            b = idom[b];
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pname_strips_version() {
        assert_eq!(pname_of("gcc-14.3.0"), "gcc");
        assert_eq!(pname_of("pkg-config-0.29.2"), "pkg-config");
        assert_eq!(pname_of("bootstrap-tools"), "bootstrap-tools");
    }

    #[test]
    fn classifies_suspects() {
        assert_eq!(classify_suspect("gcc-14.3.0"), Some(SuspectKind::Toolchain));
        assert_eq!(
            classify_suspect("meson-1.4.0"),
            Some(SuspectKind::BuildSystem)
        );
        assert_eq!(
            classify_suspect("zlib-1.3-dev"),
            Some(SuspectKind::DevOutput)
        );
        assert_eq!(classify_suspect("systemd-255"), None);
        assert_eq!(classify_suspect("bash-5.2"), None);
    }

    // Diamond: root -> a, root -> b, a -> c, b -> c. c is dominated by
    // root (two paths), so root's exclusive size is the whole graph and
    // neither a nor b exclusively owns c.
    #[test]
    fn exclusive_sizes_diamond() {
        let sizes = vec![1, 10, 20, 100]; // root, a, b, c
        let fwd = vec![vec![1, 2], vec![3], vec![3], vec![]];
        let rev = vec![vec![], vec![0], vec![0], vec![1, 2]];
        let excl = exclusive_sizes(4, 0, &fwd, &rev, &sizes);
        assert_eq!(excl[0], 131); // root dominates everything
        assert_eq!(excl[1], 10); // a alone (c is shared)
        assert_eq!(excl[2], 20); // b alone
        assert_eq!(excl[3], 100); // c itself
    }

    // Chain: root -> a -> b. a exclusively dominates b.
    #[test]
    fn exclusive_sizes_chain() {
        let sizes = vec![1, 10, 100];
        let fwd = vec![vec![1], vec![2], vec![]];
        let rev = vec![vec![], vec![0], vec![1]];
        let excl = exclusive_sizes(3, 0, &fwd, &rev, &sizes);
        assert_eq!(excl[0], 111);
        assert_eq!(excl[1], 110); // a + b
        assert_eq!(excl[2], 100);
    }
}

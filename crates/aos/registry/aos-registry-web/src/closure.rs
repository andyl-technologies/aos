//! The cache closure-graph view model: turn a flat `CacheClosure` response into
//! a tree-ordered, cycle-safe row list the SPA renders as an interactive graph.
//!
//! The hub's `BinaryCacheService.CacheClosure` RPC returns the transitive closure of a
//! store path as a flat node list — each node carrying its direct reference
//! edges (`refs`) and a `present` flag (a referenced object missing from the
//! cache appears with `present = false`). The no-JS server page renders that as
//! a plain table; the SPA progressively enhances it into an indented dependency
//! tree rooted at the requested path.
//!
//! This module is the *pure* half — model + ordering — so it compiles and is
//! unit-tested on the native workspace build. The Leptos component that paints
//! it lives in [`crate::app`] (wasm only).
//!
//! # Wire format
//!
//! The RPC's `nodes` deserialize as [`ClosureNode`]:
//!
//! ```text
//! { "store_hash": "abcd", "store_name": "abcd-foo-1.0",
//!   "file_size": 1024, "refs": ["ef01"], "present": true }
//! ```

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

/// One node of a cache closure, as returned by `BinaryCacheService.CacheClosure`.
///
/// Mirrors the `aos.hub.v1.CacheClosureNode` proto message. A node that is
/// referenced but absent from the cache carries `present = false` and no
/// meaningful `file_size`/`refs`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ClosureNode {
    /// The store-path hash component (the closure's node identity).
    pub store_hash: String,
    /// The full `<hash>-<name>` store-path basename.
    #[serde(default)]
    pub store_name: String,
    /// On-disk file size in bytes (`0` for an absent node).
    #[serde(default)]
    pub file_size: i64,
    /// Direct reference edges — the store hashes this node depends on.
    #[serde(default)]
    pub refs: Vec<String>,
    /// Whether the object is actually present in the cache.
    #[serde(default)]
    pub present: bool,
}

/// One rendered row of the closure tree, flattened in pre-order from the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureRow {
    /// Indentation depth (`0` = the root path).
    pub depth: usize,
    /// The node's store-path hash.
    pub store_hash: String,
    /// The node's display name (the `<hash>-<name>` basename, or the hash when
    /// the name is unknown for an absent node).
    pub store_name: String,
    /// A human-readable size label, or `"missing"` for an absent node.
    pub size_label: String,
    /// Whether the object is present in the cache.
    pub present: bool,
    /// Whether this row repeats a node already shown above (a shared/cyclic
    /// dependency); repeats are not expanded again, keeping the tree finite.
    pub repeat: bool,
}

/// The fully-prepared closure view: the ordered rows plus headline counts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClosureView {
    /// Pre-order rows, the root first (capped at [`MAX_ROWS`]).
    pub rows: Vec<ClosureRow>,
    /// Number of distinct present objects in the closure.
    pub present_count: usize,
    /// Number of distinct referenced objects missing from the cache.
    pub missing_count: usize,
    /// Human-readable total on-disk size of the present closure.
    pub total_label: String,
    /// Whether the row list was truncated at [`MAX_ROWS`] — a defensive cap so a
    /// response claiming far more paths than the hub would ever emit cannot
    /// freeze the tab with millions of DOM rows.
    pub truncated: bool,
}

/// The maximum number of closure rows the view will materialize.
///
/// The hub caps a closure response at 10,000 nodes; this leaves generous slack
/// for repeat rows while still bounding work if a response lies about its size.
pub const MAX_ROWS: usize = 50_000;

/// Format a byte count as a short binary-unit label (`B`/`KiB`/`MiB`/`GiB`).
///
/// Mirrors the hub's server-side `human_size` so the SPA and the no-JS page
/// agree. Negative inputs are clamped to zero.
#[must_use]
pub fn human_size(bytes: i64) -> String {
    let bytes = bytes.max(0) as u64;
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Build the [`ClosureView`] for a closure rooted at `root_hash`.
///
/// Walks the reference edges in pre-order from the root, indenting each node by
/// its depth. The walk is cycle-safe: a node reached a second time emits a
/// `repeat` row and is not expanded again, so a closure with shared or cyclic
/// dependencies still flattens to a finite tree. A reference whose target is
/// absent from `nodes` is still shown (as a missing leaf) so dangling edges are
/// visible. `total_size` is the caller-supplied present-closure byte total.
///
/// Nodes not reachable from the root (should not occur for a well-formed
/// closure) are appended after the tree at depth 0 so nothing is silently
/// dropped.
#[must_use]
pub fn build_closure_view(root_hash: &str, nodes: &[ClosureNode], total_size: i64) -> ClosureView {
    let by_hash: HashMap<&str, &ClosureNode> =
        nodes.iter().map(|n| (n.store_hash.as_str(), n)).collect();

    let mut rows = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    walk(root_hash, &by_hash, &mut seen, &mut rows);

    // Surface any unreachable nodes (defensive: a well-formed closure has none).
    for node in nodes {
        if rows.len() >= MAX_ROWS {
            break;
        }
        if !seen.contains(&node.store_hash) {
            push_row(&mut rows, 0, node.store_hash.as_str(), &by_hash, false);
            seen.insert(node.store_hash.clone());
        }
    }

    let truncated = rows.len() >= MAX_ROWS;
    rows.truncate(MAX_ROWS);
    let present_count = nodes.iter().filter(|n| n.present).count();
    let missing_count = nodes.len() - present_count;
    ClosureView {
        rows,
        present_count,
        missing_count,
        total_label: human_size(total_size),
        truncated,
    }
}

/// Pre-order DFS over the reference edges, emitting one [`ClosureRow`] per node.
///
/// Uses an explicit work stack rather than recursion: a closure is bounded only
/// by the hub's node cap, and a long dependency *chain* would otherwise recurse
/// as deeply as it is long — enough to overflow the small wasm stack.
fn walk(
    root: &str,
    by_hash: &HashMap<&str, &ClosureNode>,
    seen: &mut HashSet<String>,
    rows: &mut Vec<ClosureRow>,
) {
    // (hash, depth); children are pushed in reverse so they pop in list order.
    let mut stack: Vec<(String, usize)> = vec![(root.to_string(), 0)];
    while let Some((hash, depth)) = stack.pop() {
        if rows.len() >= MAX_ROWS {
            return;
        }
        let repeat = seen.contains(&hash);
        push_row(rows, depth, &hash, by_hash, repeat);
        if repeat {
            continue;
        }
        seen.insert(hash.clone());
        if let Some(node) = by_hash.get(hash.as_str()) {
            for child in node.refs.iter().rev() {
                stack.push((child.clone(), depth + 1));
            }
        }
    }
}

/// Append a single row for `hash`, resolving its metadata from `by_hash`.
fn push_row(
    rows: &mut Vec<ClosureRow>,
    depth: usize,
    hash: &str,
    by_hash: &HashMap<&str, &ClosureNode>,
    repeat: bool,
) {
    match by_hash.get(hash) {
        Some(node) => rows.push(ClosureRow {
            depth,
            store_hash: node.store_hash.clone(),
            store_name: if node.store_name.is_empty() {
                node.store_hash.clone()
            } else {
                node.store_name.clone()
            },
            size_label: if node.present {
                human_size(node.file_size)
            } else {
                "missing".to_string()
            },
            present: node.present,
            repeat,
        }),
        // A referenced hash with no node entry: a dangling edge. Show it as a
        // missing leaf rather than dropping it.
        None => rows.push(ClosureRow {
            depth,
            store_hash: hash.to_string(),
            store_name: hash.to_string(),
            size_label: "missing".to_string(),
            present: false,
            repeat,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(hash: &str, refs: &[&str], present: bool, size: i64) -> ClosureNode {
        ClosureNode {
            store_hash: hash.to_string(),
            store_name: format!("{hash}-pkg"),
            file_size: size,
            refs: refs.iter().map(|s| s.to_string()).collect(),
            present,
        }
    }

    #[test]
    fn human_size_uses_binary_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1024 * 1024), "1.0 MiB");
        assert_eq!(human_size(-5), "0 B");
    }

    #[test]
    fn flattens_a_tree_in_preorder_with_depths() {
        // root -> a, b ; a -> c
        let nodes = vec![
            node("root", &["a", "b"], true, 100),
            node("a", &["c"], true, 200),
            node("b", &[], true, 300),
            node("c", &[], true, 400),
        ];
        let view = build_closure_view("root", &nodes, 1000);
        let order: Vec<(usize, &str)> = view
            .rows
            .iter()
            .map(|r| (r.depth, r.store_hash.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![(0, "root"), (1, "a"), (2, "c"), (1, "b")],
            "pre-order with indentation"
        );
        assert_eq!(view.present_count, 4);
        assert_eq!(view.missing_count, 0);
        assert_eq!(view.total_label, "1000 B");
        assert!(view.rows.iter().all(|r| !r.repeat));
    }

    #[test]
    fn shared_and_cyclic_deps_terminate_as_repeats() {
        // root -> a, b ; a -> shared ; b -> shared ; shared -> root (cycle)
        let nodes = vec![
            node("root", &["a", "b"], true, 1),
            node("a", &["shared"], true, 1),
            node("b", &["shared"], true, 1),
            node("shared", &["root"], true, 1),
        ];
        let view = build_closure_view("root", &nodes, 4);
        // The second visit to `shared` (under b) and the cycle back to `root`
        // are repeats and are not expanded again.
        let repeats: Vec<&str> = view
            .rows
            .iter()
            .filter(|r| r.repeat)
            .map(|r| r.store_hash.as_str())
            .collect();
        assert!(
            repeats.contains(&"shared"),
            "shared shown twice: {repeats:?}"
        );
        assert!(repeats.contains(&"root"), "cycle back to root: {repeats:?}");
        // Every distinct node is expanded exactly once (a single non-repeat row).
        for h in ["root", "a", "b", "shared"] {
            let expanded = view
                .rows
                .iter()
                .filter(|r| r.store_hash == h && !r.repeat)
                .count();
            assert_eq!(expanded, 1, "{h} expanded once");
        }
    }

    #[test]
    fn missing_reference_is_shown_as_a_missing_leaf() {
        // root -> gone, where `gone` is referenced but absent from the cache.
        let nodes = vec![
            node("root", &["gone"], true, 10),
            ClosureNode {
                store_hash: "gone".into(),
                store_name: String::new(),
                file_size: 0,
                refs: vec![],
                present: false,
            },
        ];
        let view = build_closure_view("root", &nodes, 10);
        let gone = view
            .rows
            .iter()
            .find(|r| r.store_hash == "gone")
            .expect("missing node still rendered");
        assert!(!gone.present);
        assert_eq!(gone.size_label, "missing");
        // An absent node with no name falls back to its hash.
        assert_eq!(gone.store_name, "gone");
        assert_eq!(view.present_count, 1);
        assert_eq!(view.missing_count, 1);
    }

    #[test]
    fn dangling_edge_without_a_node_entry_is_a_missing_leaf() {
        // root references `phantom`, which has no node entry at all.
        let nodes = vec![node("root", &["phantom"], true, 5)];
        let view = build_closure_view("root", &nodes, 5);
        let phantom = view.rows.iter().find(|r| r.store_hash == "phantom");
        assert!(phantom.is_some_and(|r| !r.present && r.size_label == "missing"));
    }

    #[test]
    fn deep_chain_does_not_overflow_the_stack() {
        // A long linear dependency chain (n0 -> n1 -> ... -> n9999). Recursion
        // would blow the wasm stack; the explicit work stack handles it.
        let n = 10_000;
        let mut nodes = Vec::with_capacity(n);
        for i in 0..n {
            let refs: Vec<&str> = if i + 1 < n {
                vec![Box::leak(format!("n{}", i + 1).into_boxed_str())]
            } else {
                vec![]
            };
            nodes.push(node(
                Box::leak(format!("n{i}").into_boxed_str()),
                &refs,
                true,
                1,
            ));
        }
        let view = build_closure_view("n0", &nodes, n as i64);
        assert_eq!(view.rows.len(), n);
        assert_eq!(view.rows[0].depth, 0);
        assert_eq!(view.rows[n - 1].depth, n - 1);
        assert_eq!(view.present_count, n);
        assert!(!view.truncated);
    }

    #[test]
    fn over_cap_response_is_truncated_not_unbounded() {
        // A response far larger than the hub would ever emit: the view caps the
        // rows it materializes and flags the truncation rather than freezing.
        let n = MAX_ROWS + 1_000;
        let mut nodes = Vec::with_capacity(n);
        for i in 0..n {
            let refs: Vec<&str> = if i + 1 < n {
                vec![Box::leak(format!("n{}", i + 1).into_boxed_str())]
            } else {
                vec![]
            };
            nodes.push(node(
                Box::leak(format!("n{i}").into_boxed_str()),
                &refs,
                true,
                1,
            ));
        }
        let view = build_closure_view("n0", &nodes, n as i64);
        assert_eq!(view.rows.len(), MAX_ROWS);
        assert!(view.truncated);
    }

    #[test]
    fn deserializes_the_rpc_node_shape() {
        let json = r#"{"store_hash":"abcd","store_name":"abcd-foo-1.0",
            "file_size":1024,"refs":["ef01"],"present":true}"#;
        let node: ClosureNode = serde_json::from_str(json).unwrap();
        assert_eq!(node.store_hash, "abcd");
        assert_eq!(node.file_size, 1024);
        assert_eq!(node.refs, vec!["ef01"]);
        assert!(node.present);
    }
}

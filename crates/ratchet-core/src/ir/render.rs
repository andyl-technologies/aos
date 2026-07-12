//! A deterministic textual rendering of lowered IR for golden tests.
//!
//! [`render_ir`] dumps the whole node arena, one line per node, in allocation
//! order. It exists so simplifier-pass tests can snapshot the IR before and after
//! a pass and diff the two as reviewable text (RFC-0007
//! `docs/rfcs/0007-nix-evaluator/design-notes/simplifier-implementation-plan.md`
//! §3). The rendering is a pure function of the arena, so it is stable across
//! runs and unaffected by hashing or allocation addresses.
//!
//! The format is one header line plus one line per node:
//!
//! ```text
//! root 2
//! 0: Int spec=true Int(1)
//! 1: Int spec=true Int(2)
//! 2: BinOp spec=true Binary { op: Add, lhs: IrId(0), rhs: IrId(1) }
//! ```
//!
//! Each node line is `<index>: <IrKind> spec=<is_speculable> <IrData:?>`. Nodes
//! are keyed by their arena index (their [`IrId`]); child references appear as
//! `IrId(n)` inside the payload, so the tree is traceable by index. Source spans
//! are intentionally omitted: an arena-stable rewrite preserves spans, so
//! including them would only add noise a reviewer must ignore.

use std::fmt::Write;

use super::Ir;

/// Renders a lowered IR arena as a deterministic, one-line-per-node string.
///
/// See the [module documentation](self) for the exact format. The output is a
/// pure function of `ir`'s arena contents, suitable for golden-file comparison.
pub fn render_ir(ir: &Ir) -> String {
    let mut out = String::new();
    // Writing to a `String` is infallible, so the `fmt::Result` is discarded.
    let _ = writeln!(out, "root {}", ir.root.as_u32());
    for (index, node) in ir.arena.nodes().iter().enumerate() {
        let _ = writeln!(
            out,
            "{index}: {:?} spec={} {:?}",
            node.kind,
            node.effect.is_speculable(),
            node.data
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{lower, simplify_ir};
    use crate::scope::resolve;
    use crate::syntax::parse_str;

    fn lower_source(source: &str) -> Ir {
        let parsed = parse_str(source).expect("source parses");
        let resolved = resolve(parsed).expect("source resolves");
        lower(resolved).expect("source lowers")
    }

    #[test]
    fn render_is_deterministic() {
        let ir = lower_source("1 + 2 * 3");
        assert_eq!(render_ir(&ir), render_ir(&ir));
    }

    #[test]
    fn render_reports_the_root_and_every_node() {
        let ir = lower_source("1 + 2");
        let rendered = render_ir(&ir);
        assert!(rendered.starts_with("root "), "header names the root");
        assert_eq!(
            rendered.lines().count(),
            ir.arena.nodes().len() + 1,
            "one header line plus one line per node"
        );
        assert!(rendered.contains("BinOp"), "the add node is rendered");
        assert!(
            rendered.matches("Int(").count() >= 2,
            "both integer literals are rendered"
        );
    }

    #[test]
    fn render_is_stable_across_the_empty_simplifier() {
        for source in ["1 + 2", "let x = 1; in x + x", "if true then 1 else 2"] {
            let mut ir = lower_source(source);
            let before = render_ir(&ir);
            simplify_ir(&mut ir).expect("empty simplify succeeds");
            assert_eq!(
                before,
                render_ir(&ir),
                "the empty pass set leaves the rendered IR unchanged for `{source}`"
            );
        }
    }
}

//! Stage-1 simplifier identity gate.
//!
//! With the empty stage-1 pass set, running the simplifier over a freshly
//! lowered IR must leave the durable lowered-IR fingerprint unchanged for every
//! program in the corpus — the "zero fingerprint movement" property that keeps
//! the parse cache, JIT compiled-body cache, and eval memo keys coherent. When
//! the first real pass lands this gate is duplicated with the pass enabled versus
//! disabled; here it proves the driver itself is a faithful identity.

use crate::cache::parse::lowered_ir_fingerprint;
use crate::compile::{Ir, resolve, simplify_ir};
use crate::syntax::parse_str;
use aos_nix_dialect::nix_lower;

/// A spread of Nix programs exercising the node kinds a simplifier will match:
/// literals, arithmetic, strings with contexts, lists, plain and recursive
/// attrsets, `let`, `if`, lambdas and formal sets, application, `select`,
/// `with`, string interpolation, direct builtins, and `inherit (…)`.
const CORPUS: &[&str] = &[
    "1",
    "1 + 2 * 3 - 4",
    "\"a\" + \"b\"",
    "[ 1 2 3 ]",
    "{ a = 1; b = 2; }",
    "rec { a = 1; b = a + 1; }",
    "let x = 1; y = 2; in x + y",
    "if true then 1 else 2",
    "x: y: x + y",
    "{ a, b ? 2, ... }: a + b",
    "let f = x: x * x; in f 4",
    "let s = { a.b = 1; }; in s.a.b",
    "\"${toString 1}-${toString 2}\"",
    "with { a = 1; }; a",
    "builtins.length [ 1 2 3 ]",
    "let xs = [ 1 2 3 ]; in builtins.head xs",
    "{ inherit (builtins) length; }",
];

fn lower_nix(source: &str) -> Ir {
    let parsed = parse_str(source).expect("corpus source parses");
    let resolved = resolve(parsed).expect("corpus source resolves");
    nix_lower(resolved).expect("corpus source lowers")
}

#[test]
fn empty_pass_set_preserves_lowered_ir_fingerprint_across_corpus() {
    for source in CORPUS {
        let mut ir = lower_nix(source);
        let before = lowered_ir_fingerprint(&ir).expect("fingerprint before simplify");
        simplify_ir(&mut ir).expect("empty stage-1 simplify succeeds");
        let after = lowered_ir_fingerprint(&ir).expect("fingerprint after simplify");
        assert_eq!(
            before, after,
            "stage-1 simplifier moved the lowered-IR fingerprint for `{source}`; \
             the empty pass set must be a byte-for-byte identity"
        );
    }
}

#[test]
fn empty_pass_set_preserves_arena_and_side_tables() {
    for source in CORPUS {
        let mut simplified = lower_nix(source);
        let original = simplified.clone();
        simplify_ir(&mut simplified).expect("empty stage-1 simplify succeeds");
        assert_eq!(
            original.arena.nodes(),
            simplified.arena.nodes(),
            "node arena changed for `{source}`"
        );
        assert_eq!(
            original.arena.child_pool(),
            simplified.arena.child_pool(),
            "child pool changed for `{source}`"
        );
        assert_eq!(original.root, simplified.root, "root changed for `{source}`");
    }
}

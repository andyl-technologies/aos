//! Lowering tests for the arena IR.
//!
//! Shared fixtures live here; the test functions are split across
//! [`lowering_tests`] and [`primop_tests`] submodules.

use super::*;
use crate::syntax::{AstArena, parse_str};
use crate::{ScopeTables, resolve};

pub(super) fn lowered(source: &str) -> Ir {
    lower(resolve(parse_str(source).expect("source parses")).expect("source resolves"))
        .expect("IR lowers")
}

/// A Nix-style effect classifier mirroring the production `NixDialect` so
/// ratchet-core's own tests can exercise the dialect-supplied effect routing
/// without depending on a dialect crate.
fn nix_effect_of(kind: IrKind) -> EffectClass {
    match kind {
        IrKind::DerivationStrict => EffectClass::Effectful,
        _ => EffectClass::Pure,
    }
}

/// Lowers `source` with the Nix-style effect classifier installed, so
/// derivation nodes carry [`EffectClass::Effectful`].
pub(super) fn lowered_nix(source: &str) -> Ir {
    let resolved = resolve(parse_str(source).expect("source parses")).expect("source resolves");
    lower_with_options(
        resolved,
        IrLowerOptions::new().with_effect_of(nix_effect_of),
    )
    .expect("IR lowers")
}

pub(super) fn node(ir: &Ir, id: IrId) -> &IrNode {
    ir.arena.node(id).expect("IR node exists")
}

pub(super) fn root_node(ir: &Ir) -> &IrNode {
    node(ir, ir.root)
}

pub(super) fn thunk_inner(ir: &Ir, id: IrId) -> IrId {
    assert_eq!(node(ir, id).kind, IrKind::ThunkAlloc);
    let IrData::Node(inner) = node(ir, id).data else {
        panic!("thunk payload expected");
    };
    inner
}

pub(super) fn manual_resolved_ast(root: NodeId, nodes: Vec<Node>) -> ResolvedAst {
    let node_count = nodes.len();
    ResolvedAst {
        root,
        arena: AstArena::from_raw_parts(nodes, Vec::new()),
        symbols: SymbolTable::new(),
        scopes: ScopeTables::from_raw_parts(
            Vec::new(),
            vec![None; node_count],
            Vec::new(),
            Vec::new(),
            vec![None; node_count],
        ),
    }
}

pub(super) fn lookup_site(ir: &Ir, id: IrId) -> IrInlineCacheSiteId {
    match node(ir, id).data {
        IrData::Select { site, .. } | IrData::HasAttr { site, .. } => site,
        _ => panic!("lookup payload expected"),
    }
}

pub(super) fn symbol_text<'a>(ir: &'a Ir, symbol: Symbol) -> &'a [u8] {
    ir.symbols.resolve(symbol).expect("symbol exists")
}

mod lowering_tests;
mod primop_shadowing_tests;
mod primop_tests;
